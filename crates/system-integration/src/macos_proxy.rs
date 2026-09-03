//! macOS SystemConfiguration 原生系统代理事务。
//!
//! 所有 `unsafe` 都收口在本文件：外层状态机仍只处理普通 Rust 快照。生产接管/清除/恢复各自只创建
//! 一个 `SCPreferences` 会话、持一次锁、提交一次并应用一次，避免逐服务启动 `networksetup`。

use crate::proxy::{
    validate_mac_proxy_snapshots, validate_mac_service_ids, MacProxyPropertyValue,
    MacProxyServiceSnapshot, MacProxyTouchedSnapshot, SystemProxyStatus,
};
use crate::proxy_ops::{mac_snapshot_relation, ProxyEnableRequest, ProxySnapshotRelation};
use polaris_config_engine::user_config::system_proxy_bypass::format_bypass_for_mac;
use serde::{Deserialize, Serialize};
use std::ffi::{c_char, c_void, CStr};
use std::net::IpAddr;
use std::ptr::{null, null_mut};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

type Boolean = u8;
type CFIndex = isize;
type CFTypeId = usize;
type CFOptionFlags = usize;
type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFArrayRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFMutableDictionaryRef = *mut c_void;
type CFNumberRef = *const c_void;
type CFDataRef = *const c_void;
type CFPropertyListRef = *const c_void;
type SCPreferencesRef = *const c_void;
type SCNetworkSetRef = *const c_void;
type SCNetworkServiceRef = *const c_void;
type SCNetworkProtocolRef = *const c_void;
type SCNetworkInterfaceRef = *const c_void;
type SCDynamicStoreRef = *const c_void;

const CF_STRING_UTF8: u32 = 0x0800_0100;
const CF_NUMBER_SINT32: u32 = 3;
const CF_PROPERTY_LIST_XML_V1: CFIndex = 100;
const CF_PROPERTY_LIST_IMMUTABLE: CFOptionFlags = 0;
// Hex doubles the JSON size; 128KiB keeps the complete helper wire argument within its 256KiB
// bounded-line ceiling.
const MAX_TRANSACTION_JSON_BYTES: usize =
    polaris_helper_proto::command::mac::MAX_WIRE_LINE_BYTES / 2;
// SCPreferencesLock(wait=false) is non-blocking. Only kSCStatusPrefsBusy is safe to retry because
// no configuration mutation has happened yet. Three attempts with at most two 25ms waits bound the
// explicit contention budget to 50ms; commit/apply failures are never routed through this loop.
const PREFERENCES_LOCK_MAX_ATTEMPTS: usize = 3;
const PREFERENCES_LOCK_RETRY_DELAY: Duration = Duration::from_millis(25);
const PREFERENCES_LOCK_TOTAL_TIMEOUT: Duration = Duration::from_millis(50);
// SystemConfiguration/SCNetworkConfiguration.h: kSCStatusPrefsBusy.
const SC_STATUS_PREFS_BUSY: i32 = 3002;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
enum HelperTransaction {
    Enable {
        address: String,
        http_port: u16,
        socks_port: u16,
        bypass_list: Vec<String>,
        service_ids: Vec<String>,
    },
    Restore {
        snapshots: Vec<MacProxyServiceSnapshot>,
    },
    Clear,
    CompareEnable {
        address: String,
        http_port: u16,
        socks_port: u16,
        bypass_list: Vec<String>,
        expected_base: Vec<MacProxyServiceSnapshot>,
        desired: Vec<MacProxyServiceSnapshot>,
    },
    CompareRestore {
        originals: Vec<MacProxyServiceSnapshot>,
        expected_current: Vec<MacProxyServiceSnapshot>,
    },
}

#[allow(
    unsafe_code,
    reason = "CoreFoundation declarations are this module's native ABI boundary"
)]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CFTypeRef);
    fn CFGetTypeID(value: CFTypeRef) -> CFTypeId;
    fn CFStringGetTypeID() -> CFTypeId;
    fn CFArrayGetTypeID() -> CFTypeId;
    fn CFDictionaryGetTypeID() -> CFTypeId;
    fn CFNumberGetTypeID() -> CFTypeId;

    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        count: CFIndex,
        encoding: u32,
        external_representation: Boolean,
    ) -> CFStringRef;
    fn CFStringGetLength(value: CFStringRef) -> CFIndex;
    fn CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: u32) -> CFIndex;
    fn CFStringGetCString(
        value: CFStringRef,
        buffer: *mut c_char,
        buffer_size: CFIndex,
        encoding: u32,
    ) -> Boolean;

    fn CFArrayCreate(
        allocator: *const c_void,
        values: *const CFTypeRef,
        count: CFIndex,
        callbacks: *const c_void,
    ) -> CFArrayRef;
    fn CFArrayGetCount(array: CFArrayRef) -> CFIndex;
    fn CFArrayGetValueAtIndex(array: CFArrayRef, index: CFIndex) -> CFTypeRef;
    static kCFTypeArrayCallBacks: u8;

    fn CFDictionaryCreateMutable(
        allocator: *const c_void,
        capacity: CFIndex,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFMutableDictionaryRef;
    fn CFDictionaryCreateMutableCopy(
        allocator: *const c_void,
        capacity: CFIndex,
        dictionary: CFDictionaryRef,
    ) -> CFMutableDictionaryRef;
    fn CFDictionaryGetValue(dictionary: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;
    fn CFDictionarySetValue(dictionary: CFMutableDictionaryRef, key: CFTypeRef, value: CFTypeRef);
    fn CFDictionaryRemoveValue(dictionary: CFMutableDictionaryRef, key: CFTypeRef);
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;

    fn CFNumberCreate(
        allocator: *const c_void,
        number_type: u32,
        value: *const c_void,
    ) -> CFNumberRef;
    fn CFNumberGetValue(number: CFNumberRef, number_type: u32, value: *mut c_void) -> bool;

    fn CFDataCreate(allocator: *const c_void, bytes: *const u8, length: CFIndex) -> CFDataRef;
    fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    fn CFDataGetLength(data: CFDataRef) -> CFIndex;
    fn CFPropertyListCreateData(
        allocator: *const c_void,
        property_list: CFPropertyListRef,
        format: CFIndex,
        options: CFOptionFlags,
        error: *mut CFTypeRef,
    ) -> CFDataRef;
    fn CFPropertyListCreateWithData(
        allocator: *const c_void,
        data: CFDataRef,
        options: CFOptionFlags,
        format: *mut CFIndex,
        error: *mut CFTypeRef,
    ) -> CFPropertyListRef;
}

#[allow(
    unsafe_code,
    reason = "SystemConfiguration declarations are this module's native ABI boundary"
)]
#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCPreferencesCreate(
        allocator: *const c_void,
        name: CFStringRef,
        preferences_id: CFStringRef,
    ) -> SCPreferencesRef;
    fn SCPreferencesLock(preferences: SCPreferencesRef, wait: Boolean) -> Boolean;
    fn SCPreferencesCommitChanges(preferences: SCPreferencesRef) -> Boolean;
    fn SCPreferencesApplyChanges(preferences: SCPreferencesRef) -> Boolean;
    fn SCPreferencesUnlock(preferences: SCPreferencesRef) -> Boolean;

    fn SCNetworkSetCopyCurrent(preferences: SCPreferencesRef) -> SCNetworkSetRef;
    fn SCNetworkSetCopyServices(set: SCNetworkSetRef) -> CFArrayRef;
    fn SCNetworkServiceGetEnabled(service: SCNetworkServiceRef) -> Boolean;
    fn SCNetworkServiceGetServiceID(service: SCNetworkServiceRef) -> CFStringRef;
    fn SCNetworkServiceGetName(service: SCNetworkServiceRef) -> CFStringRef;
    fn SCNetworkServiceGetInterface(service: SCNetworkServiceRef) -> SCNetworkInterfaceRef;
    fn SCNetworkInterfaceGetBSDName(interface: SCNetworkInterfaceRef) -> CFStringRef;
    fn SCNetworkServiceCopyProtocol(
        service: SCNetworkServiceRef,
        protocol_type: CFStringRef,
    ) -> SCNetworkProtocolRef;
    fn SCNetworkServiceAddProtocolType(
        service: SCNetworkServiceRef,
        protocol_type: CFStringRef,
    ) -> Boolean;
    fn SCNetworkServiceRemoveProtocolType(
        service: SCNetworkServiceRef,
        protocol_type: CFStringRef,
    ) -> Boolean;
    fn SCNetworkProtocolGetEnabled(protocol: SCNetworkProtocolRef) -> Boolean;
    fn SCNetworkProtocolSetEnabled(protocol: SCNetworkProtocolRef, enabled: Boolean) -> Boolean;
    fn SCNetworkProtocolGetConfiguration(protocol: SCNetworkProtocolRef) -> CFDictionaryRef;
    fn SCNetworkProtocolSetConfiguration(
        protocol: SCNetworkProtocolRef,
        configuration: CFDictionaryRef,
    ) -> Boolean;

    fn SCDynamicStoreCreate(
        allocator: *const c_void,
        name: CFStringRef,
        callback: *const c_void,
        context: *mut c_void,
    ) -> SCDynamicStoreRef;
    fn SCDynamicStoreCopyValue(store: SCDynamicStoreRef, key: CFStringRef) -> CFPropertyListRef;

    fn SCError() -> i32;
    fn SCErrorString(status: i32) -> *const c_char;

    static kSCNetworkProtocolTypeProxies: CFStringRef;
    static kSCPropNetProxiesExceptionsList: CFStringRef;
    static kSCPropNetProxiesHTTPEnable: CFStringRef;
    static kSCPropNetProxiesHTTPPort: CFStringRef;
    static kSCPropNetProxiesHTTPProxy: CFStringRef;
    static kSCPropNetProxiesHTTPSEnable: CFStringRef;
    static kSCPropNetProxiesHTTPSPort: CFStringRef;
    static kSCPropNetProxiesHTTPSProxy: CFStringRef;
    static kSCPropNetProxiesSOCKSEnable: CFStringRef;
    static kSCPropNetProxiesSOCKSPort: CFStringRef;
    static kSCPropNetProxiesSOCKSProxy: CFStringRef;
}

struct OwnedCf(CFTypeRef);

impl OwnedCf {
    fn new(value: CFTypeRef, context: &str) -> Result<Self, String> {
        (!value.is_null())
            .then_some(Self(value))
            .ok_or_else(|| format!("{context} 返回空对象"))
    }

    fn raw(&self) -> CFTypeRef {
        self.0
    }
}

#[allow(
    unsafe_code,
    reason = "OwnedCf releases its non-null +1 CoreFoundation reference exactly once"
)]
impl Drop for OwnedCf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: 本结构只接管 Create/Copy 规则返回值，每个值恰好释放一次。
            unsafe { CFRelease(self.0) };
        }
    }
}

struct Preferences {
    raw: OwnedCf,
    locked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreferencesFailureKind {
    LockBusy,
    Other,
    CommitUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreferencesFailure {
    kind: PreferencesFailureKind,
    detail: String,
}

impl PreferencesFailure {
    fn other(detail: impl Into<String>) -> Self {
        Self {
            kind: PreferencesFailureKind::Other,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for PreferencesFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

#[allow(
    unsafe_code,
    reason = "SCErrorString returns a borrowed process-global C string"
)]
fn sc_failure(context: &str, kind: PreferencesFailureKind) -> PreferencesFailure {
    // SAFETY: SCError 返回当前线程最近一次 SystemConfiguration 错误；
    // SCErrorString 返回进程期不可变 C 串，此处立即拷贝。
    let status = unsafe { SCError() };
    let description = unsafe { SCErrorString(status) };
    let description = if description.is_null() {
        "unknown SystemConfiguration error".into()
    } else {
        unsafe { CStr::from_ptr(description) }
            .to_string_lossy()
            .into_owned()
    };
    PreferencesFailure {
        kind,
        detail: format!("{context} 失败：{description} (SCError={status})"),
    }
}

#[allow(
    unsafe_code,
    reason = "SCErrorString returns a borrowed process-global C string"
)]
fn sc_lock_failure(context: &str) -> PreferencesFailure {
    // Capture and classify the numeric status in one place. The localized description is diagnostic
    // only and can never influence whether a retry is safe.
    let status = unsafe { SCError() };
    let kind = if status == SC_STATUS_PREFS_BUSY {
        PreferencesFailureKind::LockBusy
    } else {
        PreferencesFailureKind::Other
    };
    let description = unsafe { SCErrorString(status) };
    let description = if description.is_null() {
        "unknown SystemConfiguration error".into()
    } else {
        unsafe { CStr::from_ptr(description) }
            .to_string_lossy()
            .into_owned()
    };
    PreferencesFailure {
        kind,
        detail: format!("{context} 失败：{description} (SCError={status})"),
    }
}

#[allow(
    unsafe_code,
    reason = "Preferences owns and serializes one SCPreferences reference"
)]
impl Preferences {
    fn open(lock_for_write: bool) -> Result<Self, PreferencesFailure> {
        let name = cf_string("Polaris System Proxy").map_err(PreferencesFailure::other)?;
        // SAFETY: name 在调用期间有效；空 prefs ID 表示默认系统 preferences。写事务只由
        // 已安装的 root helper 调用，不在前台 App 申请 SecurityAgent 交互授权。
        let raw = unsafe { SCPreferencesCreate(null(), name.raw(), null()) };
        let mut prefs = Self {
            raw: OwnedCf::new(raw, "SCPreferencesCreate").map_err(PreferencesFailure::other)?,
            locked: false,
        };
        if lock_for_write {
            // SAFETY: preferences 引用有效；wait=false 避免 configd 锁竞争时无上限阻塞。
            // 仅数值状态 kSCStatusPrefsBusy 会由 open_locked_preferences 在任何 mutation 前重试。
            if unsafe { SCPreferencesLock(prefs.raw.raw(), 0) } == 0 {
                return Err(sc_lock_failure("SCPreferencesLock"));
            }
            prefs.locked = true;
        }
        Ok(prefs)
    }

    fn commit_apply(&self) -> Result<(), PreferencesFailure> {
        // SAFETY: 调用方持有 preferences 锁，所有配置修改尚未提交。
        if unsafe { SCPreferencesCommitChanges(self.raw.raw()) } == 0 {
            return Err(sc_failure(
                "SCPreferencesCommitChanges",
                PreferencesFailureKind::CommitUnknown,
            ));
        }
        // SAFETY: commit 已成功，同一个有效 preferences 会话应用变更。
        if unsafe { SCPreferencesApplyChanges(self.raw.raw()) } == 0 {
            return Err(sc_failure(
                "SCPreferencesApplyChanges",
                PreferencesFailureKind::CommitUnknown,
            ));
        }
        Ok(())
    }
}

fn retry_preferences_lock_with<T>(
    mut acquire: impl FnMut() -> Result<T, PreferencesFailure>,
    mut wait: impl FnMut(Duration),
) -> Result<T, PreferencesFailure> {
    let started = Instant::now();
    for attempt in 1..=PREFERENCES_LOCK_MAX_ATTEMPTS {
        match acquire() {
            Ok(value) => return Ok(value),
            Err(error)
                if error.kind == PreferencesFailureKind::LockBusy
                    && attempt < PREFERENCES_LOCK_MAX_ATTEMPTS
                    && started.elapsed() < PREFERENCES_LOCK_TOTAL_TIMEOUT =>
            {
                let remaining = PREFERENCES_LOCK_TOTAL_TIMEOUT.saturating_sub(started.elapsed());
                wait(PREFERENCES_LOCK_RETRY_DELAY.min(remaining));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded preferences lock loop always returns")
}

fn open_locked_preferences() -> Result<Preferences, PreferencesFailure> {
    retry_preferences_lock_with(|| Preferences::open(true), std::thread::sleep)
}

#[allow(
    unsafe_code,
    reason = "unlocks the live SCPreferences reference before its OwnedCf drop"
)]
impl Drop for Preferences {
    fn drop(&mut self) {
        if self.locked {
            // SAFETY: 每个成功加锁的会话只在 Drop 解锁一次；错误腿同样经过这里。
            let _ = unsafe { SCPreferencesUnlock(self.raw.raw()) };
        }
    }
}

#[derive(Clone, Copy)]
struct Service {
    raw: SCNetworkServiceRef,
}

#[allow(
    unsafe_code,
    reason = "Service only borrows references retained by its owning Services array"
)]
impl Service {
    fn id(self) -> Result<String, String> {
        // SAFETY: service 由仍存活的 services array 持有，Get 返回借用 CFString。
        cf_string_to_rust(unsafe { SCNetworkServiceGetServiceID(self.raw) })
            .ok_or_else(|| "网络服务缺少稳定 service ID".into())
    }

    fn name(self) -> String {
        // SAFETY: 同上；名称允许为空，日志回落到 service ID。
        cf_string_to_rust(unsafe { SCNetworkServiceGetName(self.raw) }).unwrap_or_default()
    }

    fn enabled(self) -> bool {
        // SAFETY: service 引用有效，函数只读。
        unsafe { SCNetworkServiceGetEnabled(self.raw) != 0 }
    }

    fn manageable(self) -> bool {
        // A service is in Polaris' scope only when it owns a concrete BSD device. NetworkExtension
        // VPN/virtual services expose no BSD name and must not be rewritten merely because enabled.
        let interface = unsafe { SCNetworkServiceGetInterface(self.raw) };
        if interface.is_null() {
            return false;
        }
        cf_string_to_rust(unsafe { SCNetworkInterfaceGetBSDName(interface) })
            .is_some_and(|name| !name.is_empty())
    }
}

struct Services {
    _set: OwnedCf,
    _array: OwnedCf,
    values: Vec<Service>,
}

#[allow(
    unsafe_code,
    reason = "Services bounds-checks the retained CFArray before borrowing entries"
)]
impl Services {
    fn load(preferences: &Preferences) -> Result<Self, String> {
        // SAFETY: preferences 引用有效；Copy 规则返回值交 OwnedCf。
        let set = OwnedCf::new(
            unsafe { SCNetworkSetCopyCurrent(preferences.raw.raw()) },
            "SCNetworkSetCopyCurrent",
        )?;
        // SAFETY: set 在本作用域及返回结构中持续存活。
        let array = OwnedCf::new(
            unsafe { SCNetworkSetCopyServices(set.raw()) },
            "SCNetworkSetCopyServices",
        )?;
        // SAFETY: array 类型由 API 保证。
        let count = unsafe { CFArrayGetCount(array.raw()) };
        let mut values = Vec::with_capacity(count.max(0) as usize);
        for index in 0..count {
            // SAFETY: index 位于 0..count，array 由本结构持有。
            let raw = unsafe { CFArrayGetValueAtIndex(array.raw(), index) };
            if !raw.is_null() {
                values.push(Service { raw });
            }
        }
        Ok(Self {
            _set: set,
            _array: array,
            values,
        })
    }

    fn enabled(&self) -> impl Iterator<Item = Service> + '_ {
        self.values
            .iter()
            .copied()
            .filter(|service| service.enabled())
    }

    fn manageable(&self) -> impl Iterator<Item = Service> + '_ {
        self.enabled().filter(|service| service.manageable())
    }

    fn by_id(&self, id: &str) -> Option<Service> {
        self.values
            .iter()
            .copied()
            .find(|service| service.id().ok().as_deref() == Some(id))
    }
}

fn operation_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[allow(
    unsafe_code,
    reason = "copies a length-checked non-null CFData buffer before releasing it"
)]
fn serialize_plist(value: CFPropertyListRef) -> Result<String, String> {
    // SAFETY: value 是 SystemConfiguration 返回的合法 property-list dictionary。
    let data =
        unsafe { CFPropertyListCreateData(null(), value, CF_PROPERTY_LIST_XML_V1, 0, null_mut()) };
    let data = OwnedCf::new(data, "CFPropertyListCreateData")?;
    // SAFETY: data 引用有效，长度与指针来自同一个不可变 CFData。
    let length = unsafe { CFDataGetLength(data.raw()) };
    let bytes = unsafe { CFDataGetBytePtr(data.raw()) };
    if length <= 0 || bytes.is_null() {
        return Err("CFPropertyList data 无效".into());
    }
    // SAFETY: CFData 保证 [bytes, bytes+length) 在其生命周期内可读。
    let slice = unsafe { std::slice::from_raw_parts(bytes, length as usize) };
    String::from_utf8(slice.to_vec()).map_err(|error| format!("property-list 非 UTF-8：{error}"))
}

#[allow(
    unsafe_code,
    reason = "CFData borrows the Rust XML bytes only for synchronous plist parsing"
)]
fn deserialize_plist(xml: &str) -> Result<OwnedCf, String> {
    // SAFETY: bytes 在调用期间有效，CFDataCreate 会复制内容。
    let data = unsafe { CFDataCreate(null(), xml.as_ptr(), xml.len() as CFIndex) };
    let data = OwnedCf::new(data, "CFDataCreate")?;
    let mut format = 0;
    // SAFETY: data 有效；返回 Create 规则对象由 OwnedCf 接管。
    let plist = unsafe {
        CFPropertyListCreateWithData(
            null(),
            data.raw(),
            CF_PROPERTY_LIST_IMMUTABLE,
            &mut format,
            null_mut(),
        )
    };
    let plist = OwnedCf::new(plist, "CFPropertyListCreateWithData")?;
    // SAFETY: plist 非空；TypeID 查询无副作用。
    if unsafe { CFGetTypeID(plist.raw()) } != unsafe { CFDictionaryGetTypeID() } {
        return Err("代理快照 property-list 不是 dictionary".into());
    }
    Ok(plist)
}

#[allow(
    unsafe_code,
    reason = "CFData owns a copy while CoreFoundation parses one bounded property-list value"
)]
fn deserialize_property(xml: &str) -> Result<OwnedCf, String> {
    let data = unsafe { CFDataCreate(null(), xml.as_ptr(), xml.len() as CFIndex) };
    let data = OwnedCf::new(data, "CFDataCreate(property)")?;
    let mut format = 0;
    let value = unsafe {
        CFPropertyListCreateWithData(
            null(),
            data.raw(),
            CF_PROPERTY_LIST_IMMUTABLE,
            &mut format,
            null_mut(),
        )
    };
    OwnedCf::new(value, "CFPropertyListCreateWithData(property)")
}

#[allow(
    unsafe_code,
    reason = "CFString creation synchronously borrows the bounded UTF-8 slice"
)]
fn cf_string(value: &str) -> Result<OwnedCf, String> {
    // SAFETY: bytes 在调用期间有效，CreateWithBytes 复制内容。
    let raw = unsafe {
        CFStringCreateWithBytes(
            null(),
            value.as_ptr(),
            value.len() as CFIndex,
            CF_STRING_UTF8,
            0,
        )
    };
    OwnedCf::new(raw, "CFStringCreateWithBytes")
}

#[allow(
    unsafe_code,
    reason = "validates CF type and bounds the destination before string conversion"
)]
fn cf_string_to_rust(value: CFStringRef) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: value 来自 CF API；先验证动态类型再读。
    if unsafe { CFGetTypeID(value) } != unsafe { CFStringGetTypeID() } {
        return None;
    }
    // SAFETY: 有效 CFString。
    let length = unsafe { CFStringGetLength(value) };
    let capacity = unsafe { CFStringGetMaximumSizeForEncoding(length, CF_STRING_UTF8) } + 1;
    if capacity <= 0 {
        return Some(String::new());
    }
    let mut buffer = vec![0u8; capacity as usize];
    // SAFETY: buffer 容量已按 CoreFoundation 上界分配且可写。
    if unsafe { CFStringGetCString(value, buffer.as_mut_ptr().cast(), capacity, CF_STRING_UTF8) }
        == 0
    {
        return None;
    }
    CStr::from_bytes_until_nul(&buffer)
        .ok()
        .map(|value| value.to_string_lossy().into_owned())
}

#[allow(
    unsafe_code,
    reason = "CFNumberCreate synchronously copies one initialized i32"
)]
fn cf_number(value: i32) -> Result<OwnedCf, String> {
    // SAFETY: value 指针在调用期间有效，CFNumberCreate 会复制数值。
    let raw = unsafe { CFNumberCreate(null(), CF_NUMBER_SINT32, (&value as *const i32).cast()) };
    OwnedCf::new(raw, "CFNumberCreate")
}

#[allow(
    unsafe_code,
    reason = "dictionary and key are live retained CoreFoundation objects"
)]
fn dictionary_value(dictionary: CFDictionaryRef, key: CFStringRef) -> CFTypeRef {
    if dictionary.is_null() || key.is_null() {
        return null();
    }
    // SAFETY: dictionary/key 均来自 CoreFoundation/SystemConfiguration。
    unsafe { CFDictionaryGetValue(dictionary, key) }
}

#[allow(
    unsafe_code,
    reason = "validates the borrowed CF value type before copying an i32"
)]
fn dictionary_i32(dictionary: CFDictionaryRef, key: CFStringRef) -> Option<i32> {
    let value = dictionary_value(dictionary, key);
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFNumberGetTypeID() } {
        return None;
    }
    let mut number = 0i32;
    // SAFETY: 动态类型已验证为 CFNumber，目标是可写 i32。
    unsafe { CFNumberGetValue(value, CF_NUMBER_SINT32, (&mut number as *mut i32).cast()) }
        .then_some(number)
}

fn dictionary_string(dictionary: CFDictionaryRef, key: CFStringRef) -> Option<String> {
    cf_string_to_rust(dictionary_value(dictionary, key))
}

#[allow(
    unsafe_code,
    reason = "validates the borrowed CFArray and bounds every indexed access"
)]
fn dictionary_string_array(dictionary: CFDictionaryRef, key: CFStringRef) -> Vec<String> {
    let value = dictionary_value(dictionary, key);
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFArrayGetTypeID() } {
        return Vec::new();
    }
    let count = unsafe { CFArrayGetCount(value) };
    (0..count)
        .filter_map(|index| cf_string_to_rust(unsafe { CFArrayGetValueAtIndex(value, index) }))
        .collect()
}

fn property_value(
    dictionary: CFDictionaryRef,
    key: CFStringRef,
) -> Result<MacProxyPropertyValue, String> {
    let value = dictionary_value(dictionary, key);
    if value.is_null() {
        Ok(MacProxyPropertyValue::Absent)
    } else {
        serialize_plist(value).map(MacProxyPropertyValue::PropertyListXml)
    }
}

#[allow(
    unsafe_code,
    reason = "reads the ten bounded proxy dictionary members from immutable CF objects"
)]
fn touched_from_configuration(
    configuration: CFDictionaryRef,
    protocol_present: bool,
    protocol_enabled: bool,
) -> Result<MacProxyTouchedSnapshot, String> {
    if !protocol_present || configuration.is_null() {
        return Ok(MacProxyTouchedSnapshot {
            protocol_present,
            protocol_enabled,
            ..Default::default()
        });
    }
    // SAFETY: all keys are immutable SystemConfiguration constants and configuration is live.
    unsafe {
        Ok(MacProxyTouchedSnapshot {
            protocol_present,
            protocol_enabled,
            http_enabled: property_value(configuration, kSCPropNetProxiesHTTPEnable)?,
            http_host: property_value(configuration, kSCPropNetProxiesHTTPProxy)?,
            http_port: property_value(configuration, kSCPropNetProxiesHTTPPort)?,
            https_enabled: property_value(configuration, kSCPropNetProxiesHTTPSEnable)?,
            https_host: property_value(configuration, kSCPropNetProxiesHTTPSProxy)?,
            https_port: property_value(configuration, kSCPropNetProxiesHTTPSPort)?,
            socks_enabled: property_value(configuration, kSCPropNetProxiesSOCKSEnable)?,
            socks_host: property_value(configuration, kSCPropNetProxiesSOCKSProxy)?,
            socks_port: property_value(configuration, kSCPropNetProxiesSOCKSPort)?,
            exceptions: property_value(configuration, kSCPropNetProxiesExceptionsList)?,
        })
    }
}

#[allow(
    unsafe_code,
    reason = "captures one service's retained protocol dictionary into owned strings"
)]
fn capture_service(service: Service) -> Result<MacProxyServiceSnapshot, String> {
    let service_id = service.id()?;
    let mut service_name = service.name();
    if service_name.is_empty() {
        service_name.clone_from(&service_id);
    }
    let Some(protocol) = protocol(service, false)? else {
        return Ok(MacProxyServiceSnapshot {
            service_id,
            service_name,
            service_enabled: true,
            touched: Some(MacProxyTouchedSnapshot::default()),
            ..Default::default()
        });
    };
    // SAFETY: protocol is retained for this function.
    let protocol_enabled = unsafe { SCNetworkProtocolGetEnabled(protocol.raw()) != 0 };
    let configuration = unsafe { SCNetworkProtocolGetConfiguration(protocol.raw()) };
    let (configuration_plist, status, touched) = if configuration.is_null() {
        (
            None,
            SystemProxyStatus::default(),
            touched_from_configuration(configuration, true, protocol_enabled)?,
        )
    } else {
        (
            Some(serialize_plist(configuration)?),
            status_from_configuration(configuration, protocol_enabled),
            touched_from_configuration(configuration, true, protocol_enabled)?,
        )
    };
    Ok(MacProxyServiceSnapshot {
        service_id,
        service_name,
        service_enabled: true,
        had_proxy_protocol: true,
        protocol_enabled,
        configuration_plist,
        status,
        touched: Some(touched),
        clear_on_restore: false,
    })
}

fn capture_manageable_services(
    services: &Services,
) -> Result<Vec<MacProxyServiceSnapshot>, String> {
    services.manageable().map(capture_service).collect()
}

#[allow(
    unsafe_code,
    reason = "reads only type-checked values from the live proxy dictionary"
)]
fn status_from_configuration(
    configuration: CFDictionaryRef,
    protocol_enabled: bool,
) -> SystemProxyStatus {
    let proxy = |enable: CFStringRef, host: CFStringRef, port: CFStringRef| {
        (dictionary_i32(configuration, enable) == Some(1)).then(|| {
            let host = dictionary_string(configuration, host)?;
            let port = dictionary_i32(configuration, port)?;
            (!host.is_empty() && (1..=65_535).contains(&port)).then(|| format!("{host}:{port}"))
        })?
    };
    let mut status = SystemProxyStatus {
        // SAFETY: schema constants are immutable process-lifetime CFString objects.
        http_proxy: proxy(
            unsafe { kSCPropNetProxiesHTTPEnable },
            unsafe { kSCPropNetProxiesHTTPProxy },
            unsafe { kSCPropNetProxiesHTTPPort },
        ),
        https_proxy: proxy(
            unsafe { kSCPropNetProxiesHTTPSEnable },
            unsafe { kSCPropNetProxiesHTTPSProxy },
            unsafe { kSCPropNetProxiesHTTPSPort },
        ),
        socks_proxy: proxy(
            unsafe { kSCPropNetProxiesSOCKSEnable },
            unsafe { kSCPropNetProxiesSOCKSProxy },
            unsafe { kSCPropNetProxiesSOCKSPort },
        ),
        bypass_domains: Some(dictionary_string_array(configuration, unsafe {
            kSCPropNetProxiesExceptionsList
        })),
        enabled: false,
    };
    status.enabled = protocol_enabled && status.has_any_proxy();
    status
}

#[allow(
    unsafe_code,
    reason = "copies or creates one retained proxy protocol reference"
)]
fn protocol(service: Service, create: bool) -> Result<Option<OwnedCf>, String> {
    // SAFETY: service 有效，常量为进程期 CFString。
    let mut raw =
        unsafe { SCNetworkServiceCopyProtocol(service.raw, kSCNetworkProtocolTypeProxies) };
    if raw.is_null() && create {
        // SAFETY: preferences 已加锁，service 属当前 set。
        if unsafe { SCNetworkServiceAddProtocolType(service.raw, kSCNetworkProtocolTypeProxies) }
            == 0
        {
            return Err(format!(
                "为网络服务 {} 添加 Proxies 协议失败",
                service.name()
            ));
        }
        raw = unsafe { SCNetworkServiceCopyProtocol(service.raw, kSCNetworkProtocolTypeProxies) };
    }
    if raw.is_null() {
        Ok(None)
    } else {
        OwnedCf::new(raw, "SCNetworkServiceCopyProtocol").map(Some)
    }
}

#[allow(
    unsafe_code,
    reason = "copies the live protocol dictionary into a new mutable reference"
)]
fn mutable_configuration(protocol: SCNetworkProtocolRef) -> Result<OwnedCf, String> {
    // SAFETY: protocol 有效，Get 返回借用字典或 null。
    let configuration = unsafe { SCNetworkProtocolGetConfiguration(protocol) };
    let raw = if configuration.is_null() {
        return empty_configuration();
    } else {
        // SAFETY: configuration 是有效 CFDictionary，CreateMutableCopy 返回独立对象。
        unsafe { CFDictionaryCreateMutableCopy(null(), 0, configuration) }
    };
    OwnedCf::new(raw, "创建可变 Proxies dictionary")
}

#[allow(
    unsafe_code,
    reason = "creates one empty retained mutable CoreFoundation dictionary"
)]
fn empty_configuration() -> Result<OwnedCf, String> {
    // SAFETY: callback 常量是 CoreFoundation 进程期静态对象。
    let raw = unsafe {
        CFDictionaryCreateMutable(
            null(),
            0,
            (&raw const kCFTypeDictionaryKeyCallBacks).cast(),
            (&raw const kCFTypeDictionaryValueCallBacks).cast(),
        )
    };
    OwnedCf::new(raw, "创建空 Proxies dictionary")
}

#[allow(
    unsafe_code,
    reason = "dictionary, key and value remain live for the synchronous set call"
)]
fn set_dictionary_value(dictionary: CFMutableDictionaryRef, key: CFStringRef, value: CFTypeRef) {
    // SAFETY: dictionary 可变且三者在调用期间有效；字典 callbacks 会 retain key/value。
    unsafe { CFDictionarySetValue(dictionary, key, value) };
}

#[allow(
    unsafe_code,
    reason = "mutates only the live retained dictionary and restores one serialized member"
)]
fn restore_property_value(
    dictionary: CFMutableDictionaryRef,
    key: CFStringRef,
    value: &MacProxyPropertyValue,
) -> Result<(), String> {
    match value {
        MacProxyPropertyValue::Absent => {
            // SAFETY: dictionary is mutable and key is a live schema constant.
            unsafe { CFDictionaryRemoveValue(dictionary, key) };
            Ok(())
        }
        MacProxyPropertyValue::PropertyListXml(xml) => {
            let property = deserialize_property(xml)?;
            // SAFETY: callbacks retain the deserialized property for the synchronous set.
            unsafe { CFDictionarySetValue(dictionary, key, property.raw()) };
            Ok(())
        }
    }
}

#[allow(
    unsafe_code,
    reason = "restores exactly the ten Polaris-owned members and leaves every other key intact"
)]
fn restore_touched_configuration(
    configuration: CFMutableDictionaryRef,
    touched: &MacProxyTouchedSnapshot,
) -> Result<(), String> {
    // SAFETY: all keys are immutable process-lifetime schema constants.
    let entries = unsafe {
        [
            (kSCPropNetProxiesHTTPEnable, &touched.http_enabled),
            (kSCPropNetProxiesHTTPProxy, &touched.http_host),
            (kSCPropNetProxiesHTTPPort, &touched.http_port),
            (kSCPropNetProxiesHTTPSEnable, &touched.https_enabled),
            (kSCPropNetProxiesHTTPSProxy, &touched.https_host),
            (kSCPropNetProxiesHTTPSPort, &touched.https_port),
            (kSCPropNetProxiesSOCKSEnable, &touched.socks_enabled),
            (kSCPropNetProxiesSOCKSProxy, &touched.socks_host),
            (kSCPropNetProxiesSOCKSPort, &touched.socks_port),
            (kSCPropNetProxiesExceptionsList, &touched.exceptions),
        ]
    };
    for (key, value) in entries {
        restore_property_value(configuration, key, value)?;
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "writes retained proxy values into the live mutable dictionary"
)]
fn set_static_proxy_configuration(
    configuration: CFMutableDictionaryRef,
    request: &ProxyEnableRequest,
) -> Result<(), String> {
    let address = cf_string(&request.address)?;
    let http_port = cf_number(i32::from(request.http_port))?;
    let socks_port = cf_number(i32::from(request.socks_port))?;
    let enabled = cf_number(1)?;
    for (enable_key, host_key, port_key, port) in [
        (
            unsafe { kSCPropNetProxiesHTTPEnable },
            unsafe { kSCPropNetProxiesHTTPProxy },
            unsafe { kSCPropNetProxiesHTTPPort },
            http_port.raw(),
        ),
        (
            unsafe { kSCPropNetProxiesHTTPSEnable },
            unsafe { kSCPropNetProxiesHTTPSProxy },
            unsafe { kSCPropNetProxiesHTTPSPort },
            http_port.raw(),
        ),
        (
            unsafe { kSCPropNetProxiesSOCKSEnable },
            unsafe { kSCPropNetProxiesSOCKSProxy },
            unsafe { kSCPropNetProxiesSOCKSPort },
            socks_port.raw(),
        ),
    ] {
        set_dictionary_value(configuration, enable_key, enabled.raw());
        set_dictionary_value(configuration, host_key, address.raw());
        set_dictionary_value(configuration, port_key, port);
    }

    let bypass_values = format_bypass_for_mac(&request.bypass_list)
        .into_iter()
        .filter(|value| value != "Empty")
        .map(|value| cf_string(&value))
        .collect::<Result<Vec<_>, _>>()?;
    let pointers = bypass_values.iter().map(OwnedCf::raw).collect::<Vec<_>>();
    // SAFETY: values 在 CFArrayCreate 调用期间有效；type callbacks retain 每个字符串。
    let bypass = unsafe {
        CFArrayCreate(
            null(),
            if pointers.is_empty() {
                null()
            } else {
                pointers.as_ptr()
            },
            pointers.len() as CFIndex,
            (&raw const kCFTypeArrayCallBacks).cast(),
        )
    };
    let bypass = OwnedCf::new(bypass, "CFArrayCreate(bypass)")?;
    set_dictionary_value(
        configuration,
        unsafe { kSCPropNetProxiesExceptionsList },
        bypass.raw(),
    );
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "writes retained disable values into the live mutable dictionary"
)]
fn clear_static_proxy_configuration(configuration: CFMutableDictionaryRef) -> Result<(), String> {
    let disabled = cf_number(0)?;
    for key in [
        unsafe { kSCPropNetProxiesHTTPEnable },
        unsafe { kSCPropNetProxiesHTTPSEnable },
        unsafe { kSCPropNetProxiesSOCKSEnable },
    ] {
        set_dictionary_value(configuration, key, disabled.raw());
    }
    Ok(())
}

fn apply_mutation(
    label: &str,
    mutate: impl FnOnce(&Services) -> Result<usize, String>,
) -> Result<usize, String> {
    let _guard = operation_lock()
        .lock()
        .map_err(|_| "macOS 系统代理事务锁已损坏".to_string())?;
    let started = Instant::now();
    let preferences = open_locked_preferences().map_err(|error| error.to_string())?;
    let services = Services::load(&preferences)?;
    let changed = mutate(&services)?;
    preferences
        .commit_apply()
        .map_err(|error| error.to_string())?;
    log::info!(
        "macOS SystemConfiguration {label}：服务数={changed}，单事务耗时={}ms",
        started.elapsed().as_millis()
    );
    Ok(changed)
}

#[allow(
    unsafe_code,
    reason = "captures type-checked protocol dictionaries before returning owned snapshots"
)]
pub(crate) fn capture_all() -> Result<Vec<MacProxyServiceSnapshot>, String> {
    let _guard = operation_lock()
        .lock()
        .map_err(|_| "macOS 系统代理事务锁已损坏".to_string())?;
    let preferences = Preferences::open(false).map_err(|error| error.to_string())?;
    let services = Services::load(&preferences)?;
    capture_manageable_services(&services)
}

#[allow(
    unsafe_code,
    reason = "creates a mutable copy of an owned property-list dictionary"
)]
pub(crate) fn build_applied_snapshots(
    request: &ProxyEnableRequest,
    bases: &[MacProxyServiceSnapshot],
) -> Result<Vec<MacProxyServiceSnapshot>, String> {
    validate_proxy_request(request)?;
    validate_mac_proxy_snapshots(bases, None)?;
    let bypass = format_bypass_for_mac(&request.bypass_list)
        .into_iter()
        .filter(|value| value != "Empty")
        .collect::<Vec<_>>();
    let desired = bases
        .iter()
        .map(|base| {
            let configuration = match base.configuration_plist.as_deref() {
                Some(xml) => deserialize_plist(xml).and_then(|plist| {
                    // Create a mutable copy because deserialization returns an immutable plist.
                    let mutable =
                        unsafe { CFDictionaryCreateMutableCopy(null(), 0, plist.raw().cast()) };
                    OwnedCf::new(mutable, "复制 applied Proxies dictionary")
                })?,
                None => empty_configuration()?,
            };
            set_static_proxy_configuration(configuration.0.cast_mut(), request)?;
            let configuration_plist = serialize_plist(configuration.raw())?;
            let touched = touched_from_configuration(configuration.raw(), true, true)?;
            Ok(MacProxyServiceSnapshot {
                service_id: base.service_id.clone(),
                service_name: base.service_name.clone(),
                service_enabled: true,
                had_proxy_protocol: true,
                protocol_enabled: true,
                configuration_plist: Some(configuration_plist),
                status: SystemProxyStatus {
                    enabled: true,
                    http_proxy: Some(request.our_host_port()),
                    https_proxy: Some(request.our_host_port()),
                    socks_proxy: Some(format!("{}:{}", request.address, request.socks_port)),
                    bypass_domains: Some(bypass.clone()),
                },
                touched: Some(touched),
                clear_on_restore: false,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    validate_mac_proxy_snapshots(bases, Some(&desired))?;
    Ok(desired)
}

fn ownership_matches(
    expected: &[MacProxyServiceSnapshot],
    current: &[MacProxyServiceSnapshot],
) -> bool {
    matches!(
        mac_snapshot_relation(expected, expected, current),
        ProxySnapshotRelation::Unchanged | ProxySnapshotRelation::Exact
    )
}

fn snapshots_equal_by_id(
    expected: &[MacProxyServiceSnapshot],
    current: &[MacProxyServiceSnapshot],
) -> bool {
    validate_mac_proxy_snapshots(expected, Some(current)).is_ok()
        && expected.iter().all(|expected| {
            current
                .iter()
                .find(|current| current.service_id == expected.service_id)
                == Some(expected)
        })
}

#[allow(
    unsafe_code,
    reason = "restores only exact captured members while the preferences transaction owns all CF refs"
)]
fn restore_exact_members(
    services: &Services,
    originals: &[MacProxyServiceSnapshot],
) -> Result<usize, String> {
    let mut changed = 0;
    for original in originals {
        let Some(service) = services.by_id(&original.service_id) else {
            return Err(format!(
                "恢复 macOS 系统代理时网络服务已不存在：{} ({})",
                original.service_name, original.service_id
            ));
        };
        if !service.enabled() || !service.manageable() {
            return Err(format!(
                "恢复 macOS 系统代理时网络服务已停用或不再可管理：{} ({})",
                original.service_name, original.service_id
            ));
        }
        if original.clear_on_restore {
            let Some(protocol) = protocol(service, false)? else {
                continue;
            };
            let configuration = mutable_configuration(protocol.raw())?;
            clear_static_proxy_configuration(configuration.0.cast_mut())?;
            if unsafe { SCNetworkProtocolSetConfiguration(protocol.raw(), configuration.raw()) }
                == 0
            {
                return Err(format!("清除自指代理失败：{}", original.service_name));
            }
            changed += 1;
            continue;
        }
        if !original.had_proxy_protocol {
            if protocol(service, false)?.is_some()
                && unsafe {
                    SCNetworkServiceRemoveProtocolType(service.raw, kSCNetworkProtocolTypeProxies)
                } == 0
            {
                return Err(format!(
                    "移除新增 Proxies 协议失败：{}",
                    original.service_name
                ));
            }
            changed += 1;
            continue;
        }
        // A present protocol with NULL configuration has ambiguous platform semantics. Do not
        // invent an empty dictionary and claim exact restoration until attended hardware proves it.
        if original.configuration_plist.is_none() {
            return Err(format!(
                "网络服务 {} 的原 Proxies configuration 为 NULL，拒绝有损恢复",
                original.service_name
            ));
        }
        let touched = original
            .touched
            .as_ref()
            .ok_or_else(|| format!("网络服务 {} 缺少 touched 快照", original.service_name))?;
        let protocol = protocol(service, false)?
            .ok_or_else(|| format!("恢复时 Proxies 协议缺失：{}", original.service_name))?;
        let configuration = mutable_configuration(protocol.raw())?;
        restore_touched_configuration(configuration.0.cast_mut(), touched)?;
        if unsafe { SCNetworkProtocolSetConfiguration(protocol.raw(), configuration.raw()) } == 0
            || unsafe {
                SCNetworkProtocolSetEnabled(protocol.raw(), u8::from(touched.protocol_enabled))
            } == 0
        {
            return Err(format!("恢复网络服务代理失败：{}", original.service_name));
        }
        changed += 1;
    }
    Ok(changed)
}

fn compare_and_enable(
    request: &ProxyEnableRequest,
    expected_base: &[MacProxyServiceSnapshot],
    desired: &[MacProxyServiceSnapshot],
) -> Result<(), String> {
    validate_proxy_request(request)?;
    validate_mac_proxy_snapshots(expected_base, Some(desired))?;
    let _guard = operation_lock()
        .lock()
        .map_err(|_| "macOS 系统代理事务锁已损坏".to_string())?;
    let preferences = open_locked_preferences().map_err(|error| error.to_string())?;
    let services = Services::load(&preferences)?;
    let current = capture_manageable_services(&services)?;
    if !ownership_matches(expected_base, &current) {
        return Err("macOS 系统代理 enable 前所有权已变化".into());
    }
    let deterministic = build_applied_snapshots(request, expected_base)?;
    if !snapshots_equal_by_id(&deterministic, desired) {
        return Err("macOS 系统代理 desired payload 与请求不一致".into());
    }
    let changed = enable_in_services(request, expected_base, &services)?;
    preferences
        .commit_apply()
        .map_err(|error| error.to_string())?;
    log::info!("macOS SystemConfiguration compare-and-enable：服务数={changed}");
    Ok(())
}

fn compare_and_restore(
    originals: &[MacProxyServiceSnapshot],
    expected_current: &[MacProxyServiceSnapshot],
) -> Result<(), String> {
    validate_mac_proxy_snapshots(originals, Some(expected_current))?;
    let _guard = operation_lock()
        .lock()
        .map_err(|_| "macOS 系统代理事务锁已损坏".to_string())?;
    let preferences = open_locked_preferences().map_err(|error| error.to_string())?;
    let services = Services::load(&preferences)?;
    let current = capture_manageable_services(&services)?;
    if !ownership_matches(expected_current, &current) {
        return Err("macOS 系统代理 restore 前所有权已变化".into());
    }
    validate_absent_protocol_removal(originals, expected_current, &current)?;
    let changed = restore_exact_members(&services, originals)?;
    preferences
        .commit_apply()
        .map_err(|error| error.to_string())?;
    log::info!("macOS SystemConfiguration compare-and-restore：服务数={changed}");
    Ok(())
}

fn validate_absent_protocol_removal(
    originals: &[MacProxyServiceSnapshot],
    expected_current: &[MacProxyServiceSnapshot],
    current: &[MacProxyServiceSnapshot],
) -> Result<(), String> {
    validate_mac_proxy_snapshots(originals, Some(expected_current))?;
    validate_mac_proxy_snapshots(expected_current, Some(current))?;
    // Removing a protocol that was absent originally would also remove concurrent unowned keys.
    // For this special case require the full live configuration to still equal the expected one.
    for original in originals
        .iter()
        .filter(|snapshot| !snapshot.had_proxy_protocol)
    {
        let expected = expected_current
            .iter()
            .find(|snapshot| snapshot.service_id == original.service_id)
            .ok_or_else(|| "macOS restore expected service scope mismatch".to_string())?;
        let live = current
            .iter()
            .find(|snapshot| snapshot.service_id == original.service_id)
            .ok_or_else(|| "macOS restore live service scope mismatch".to_string())?;
        if live.configuration_plist != expected.configuration_plist
            || live.protocol_enabled != expected.protocol_enabled
        {
            return Err(format!(
                "网络服务 {} 新建 protocol 含并发未触字段，拒绝删除",
                original.service_name
            ));
        }
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "commits retained dictionaries only while service/protocol owners remain live"
)]
fn enable_in_services(
    request: &ProxyEnableRequest,
    captured: &[MacProxyServiceSnapshot],
    services: &Services,
) -> Result<usize, String> {
    let mut changed = 0;
    for snapshot in captured {
        let Some(service) = services.by_id(&snapshot.service_id) else {
            return Err(format!(
                "macOS 网络服务在快照后已移除：{}",
                snapshot.service_id
            ));
        };
        if !service.enabled() || !service.manageable() {
            return Err(format!(
                "macOS 网络服务在快照后已停用或不再可管理：{}",
                snapshot.service_id
            ));
        }
        let protocol = protocol(service, true)?
            .ok_or_else(|| format!("网络服务 {} 的 Proxies 协议不可用", service.name()))?;
        let configuration = mutable_configuration(protocol.raw())?;
        set_static_proxy_configuration(configuration.0.cast_mut(), request)?;
        if unsafe { SCNetworkProtocolSetConfiguration(protocol.raw(), configuration.raw()) } == 0
            || unsafe { SCNetworkProtocolSetEnabled(protocol.raw(), 1) } == 0
        {
            return Err(format!("写入网络服务 {} 的代理配置失败", service.name()));
        }
        changed += 1;
    }
    Ok(changed)
}

#[allow(
    unsafe_code,
    reason = "commits retained dictionaries only while service/protocol owners remain live"
)]
pub(crate) fn enable(
    request: &ProxyEnableRequest,
    captured_service_ids: Option<&[String]>,
) -> Result<(), String> {
    apply_mutation("接管", |services| {
        let captured = match captured_service_ids {
            Some(ids) => ids
                .iter()
                .map(|id| MacProxyServiceSnapshot {
                    service_id: id.clone(),
                    ..Default::default()
                })
                .collect::<Vec<_>>(),
            None => capture_manageable_services(services)?,
        };
        enable_in_services(request, &captured, services)
    })
    .map(|_| ())
}

#[allow(
    unsafe_code,
    reason = "commits retained dictionaries only while service/protocol owners remain live"
)]
pub(crate) fn clear() -> Result<(), String> {
    apply_mutation("清除", |services| {
        let mut changed = 0;
        // 与 enable 的射程对称：不碰当时已停用、Polaris 从未接管的服务。
        for service in services.manageable() {
            let Some(protocol) = protocol(service, false)? else {
                continue;
            };
            let configuration = mutable_configuration(protocol.raw())?;
            clear_static_proxy_configuration(configuration.0.cast_mut())?;
            // SAFETY: protocol/configuration 有效且 preferences 持锁。
            if unsafe { SCNetworkProtocolSetConfiguration(protocol.raw(), configuration.raw()) }
                == 0
            {
                return Err(format!("关闭网络服务 {} 的代理配置失败", service.name()));
            }
            changed += 1;
        }
        Ok(changed)
    })
    .map(|_| ())
}

#[allow(
    unsafe_code,
    reason = "restores retained dictionaries only while service/protocol owners remain live"
)]
pub(crate) fn restore(snapshots: &[MacProxyServiceSnapshot]) -> Result<(), String> {
    validate_mac_proxy_snapshots(snapshots, None)?;
    apply_mutation("恢复", |services| {
        let mut changed = 0;
        for snapshot in snapshots {
            let Some(service) = services.by_id(&snapshot.service_id) else {
                log::warn!(
                    "恢复 macOS 系统代理时网络服务已不存在，跳过：{} ({})",
                    snapshot.service_name,
                    snapshot.service_id
                );
                continue;
            };
            if snapshot.clear_on_restore {
                let Some(protocol) = protocol(service, false)? else {
                    continue;
                };
                let configuration = mutable_configuration(protocol.raw())?;
                clear_static_proxy_configuration(configuration.0.cast_mut())?;
                if unsafe { SCNetworkProtocolSetConfiguration(protocol.raw(), configuration.raw()) }
                    == 0
                {
                    return Err(format!("清除自指代理失败：{}", snapshot.service_name));
                }
                changed += 1;
                continue;
            }
            if !snapshot.had_proxy_protocol {
                if protocol(service, false)?.is_some()
                    && unsafe {
                        SCNetworkServiceRemoveProtocolType(
                            service.raw,
                            kSCNetworkProtocolTypeProxies,
                        )
                    } == 0
                {
                    return Err(format!(
                        "移除新增 Proxies 协议失败：{}",
                        snapshot.service_name
                    ));
                }
                changed += 1;
                continue;
            }
            let protocol = protocol(service, true)?
                .ok_or_else(|| format!("恢复时 Proxies 协议不可用：{}", snapshot.service_name))?;
            let configuration = match snapshot.configuration_plist.as_deref() {
                Some(xml) => deserialize_plist(xml)?,
                // 原协议存在但 configuration 为 null：必须恢复为空字典。复用当前
                // configuration 会把 Polaris 刚写入的地址原样保留，形成死端口。
                None => empty_configuration()?,
            };
            if unsafe { SCNetworkProtocolSetConfiguration(protocol.raw(), configuration.raw()) }
                == 0
                || unsafe {
                    SCNetworkProtocolSetEnabled(protocol.raw(), u8::from(snapshot.protocol_enabled))
                } == 0
            {
                return Err(format!("恢复网络服务代理失败：{}", snapshot.service_name));
            }
            changed += 1;
        }
        Ok(changed)
    })
    .map(|_| ())
}

fn encode_transaction(transaction: &HelperTransaction) -> Result<String, String> {
    let json = serde_json::to_vec(transaction)
        .map_err(|error| format!("序列化 macOS 系统代理事务失败：{error}"))?;
    if json.len() > MAX_TRANSACTION_JSON_BYTES {
        return Err(format!(
            "macOS 系统代理事务过大：{} > {MAX_TRANSACTION_JSON_BYTES} bytes",
            json.len()
        ));
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(json.len() * 2);
    for byte in json {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    Ok(encoded)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_transaction(payload_hex: &str) -> Result<HelperTransaction, String> {
    if !payload_hex.len().is_multiple_of(2) {
        return Err("macOS 系统代理事务 hex 长度必须为偶数".into());
    }
    let decoded_len = payload_hex.len() / 2;
    if decoded_len == 0 || decoded_len > MAX_TRANSACTION_JSON_BYTES {
        return Err(format!("macOS 系统代理事务大小非法：{decoded_len} bytes"));
    }
    let bytes = payload_hex.as_bytes();
    let mut decoded = Vec::with_capacity(decoded_len);
    for pair in bytes.as_chunks::<2>().0 {
        let high = decode_hex_nibble(pair[0])
            .ok_or_else(|| "macOS 系统代理事务含非法 hex 字符".to_string())?;
        let low = decode_hex_nibble(pair[1])
            .ok_or_else(|| "macOS 系统代理事务含非法 hex 字符".to_string())?;
        decoded.push((high << 4) | low);
    }
    serde_json::from_slice(&decoded)
        .map_err(|error| format!("解析 macOS 系统代理事务失败：{error}"))
}

fn validate_proxy_request(request: &ProxyEnableRequest) -> Result<(), String> {
    let address = request
        .address
        .parse::<IpAddr>()
        .map_err(|_| "macOS 系统代理 helper 只接受回环 IP".to_string())?;
    if !address.is_loopback() || request.http_port == 0 || request.socks_port == 0 {
        return Err("macOS 系统代理 helper 只接受回环 IP 与非零端口".into());
    }
    if request
        .bypass_list
        .iter()
        .any(|entry| entry.len() > 4096 || entry.contains(['\0', '\r', '\n']))
    {
        return Err("macOS 系统代理 bypass 条目非法".into());
    }
    Ok(())
}

pub(crate) fn enable_transaction_payload(
    request: &ProxyEnableRequest,
    service_ids: Vec<String>,
) -> Result<String, String> {
    validate_proxy_request(request)?;
    validate_mac_service_ids(service_ids.iter().map(String::as_str))?;
    encode_transaction(&HelperTransaction::Enable {
        address: request.address.clone(),
        http_port: request.http_port,
        socks_port: request.socks_port,
        bypass_list: request.bypass_list.clone(),
        service_ids,
    })
}

pub(crate) fn restore_transaction_payload(
    snapshots: &[MacProxyServiceSnapshot],
) -> Result<String, String> {
    validate_mac_proxy_snapshots(snapshots, None)?;
    encode_transaction(&HelperTransaction::Restore {
        snapshots: snapshots.to_vec(),
    })
}

pub(crate) fn enable_transaction_payload_v2(
    request: &ProxyEnableRequest,
    expected_base: &[MacProxyServiceSnapshot],
    desired: &[MacProxyServiceSnapshot],
) -> Result<String, String> {
    validate_proxy_request(request)?;
    validate_mac_proxy_snapshots(expected_base, Some(desired))?;
    encode_transaction(&HelperTransaction::CompareEnable {
        address: request.address.clone(),
        http_port: request.http_port,
        socks_port: request.socks_port,
        bypass_list: request.bypass_list.clone(),
        expected_base: expected_base.to_vec(),
        desired: desired.to_vec(),
    })
}

pub(crate) fn restore_transaction_payload_v2(
    originals: &[MacProxyServiceSnapshot],
    expected_current: &[MacProxyServiceSnapshot],
) -> Result<String, String> {
    validate_mac_proxy_snapshots(originals, Some(expected_current))?;
    encode_transaction(&HelperTransaction::CompareRestore {
        originals: originals.to_vec(),
        expected_current: expected_current.to_vec(),
    })
}

pub(crate) fn clear_transaction_payload() -> Result<String, String> {
    encode_transaction(&HelperTransaction::Clear)
}

pub(crate) fn execute_transaction(payload_hex: &str) -> Result<(), String> {
    match decode_transaction(payload_hex)? {
        HelperTransaction::Enable {
            address,
            http_port,
            socks_port,
            bypass_list,
            service_ids,
        } => {
            validate_mac_service_ids(service_ids.iter().map(String::as_str))?;
            let request = ProxyEnableRequest {
                address,
                http_port,
                socks_port,
                bypass_list,
            };
            validate_proxy_request(&request)?;
            enable(&request, Some(&service_ids))
        }
        HelperTransaction::Restore { snapshots } => {
            validate_mac_proxy_snapshots(&snapshots, None)?;
            restore(&snapshots)
        }
        HelperTransaction::Clear => clear(),
        HelperTransaction::CompareEnable {
            address,
            http_port,
            socks_port,
            bypass_list,
            expected_base,
            desired,
        } => {
            let request = ProxyEnableRequest {
                address,
                http_port,
                socks_port,
                bypass_list,
            };
            validate_proxy_request(&request)?;
            compare_and_enable(&request, &expected_base, &desired)
        }
        HelperTransaction::CompareRestore {
            originals,
            expected_current,
        } => compare_and_restore(&originals, &expected_current),
    }
}

#[allow(
    unsafe_code,
    reason = "reads type-checked protocol dictionaries under the operation lock"
)]
fn read_statuses() -> Result<Vec<(String, SystemProxyStatus)>, String> {
    let _guard = operation_lock()
        .lock()
        .map_err(|_| "macOS 系统代理事务锁已损坏".to_string())?;
    let preferences = Preferences::open(false).map_err(|error| error.to_string())?;
    let services = Services::load(&preferences)?;
    services
        .enabled()
        .map(|service| {
            let id = service.id()?;
            let status = match protocol(service, false)? {
                None => SystemProxyStatus::default(),
                Some(protocol) => {
                    let configuration =
                        unsafe { SCNetworkProtocolGetConfiguration(protocol.raw()) };
                    if configuration.is_null() {
                        SystemProxyStatus::default()
                    } else {
                        status_from_configuration(configuration, unsafe {
                            SCNetworkProtocolGetEnabled(protocol.raw()) != 0
                        })
                    }
                }
            };
            Ok((id, status))
        })
        .collect()
}

pub(crate) fn read_any_status() -> Result<SystemProxyStatus, String> {
    Ok(read_statuses()?
        .into_iter()
        .map(|(_, status)| status)
        .find(|status| status.enabled)
        .unwrap_or_default())
}

#[allow(
    unsafe_code,
    reason = "copies and type-checks the dynamic-store primary service dictionary"
)]
fn primary_service_id() -> Option<String> {
    let name = cf_string("Polaris Primary Service").ok()?;
    // SAFETY: callback/context 为空表示只读 store；Create 返回值由 OwnedCf 接管。
    let store = unsafe { SCDynamicStoreCreate(null(), name.raw(), null(), null_mut()) };
    let store = OwnedCf::new(store, "SCDynamicStoreCreate").ok()?;
    let key = cf_string("State:/Network/Global/IPv4").ok()?;
    // SAFETY: store/key 有效；Copy 规则返回值由 OwnedCf 接管。
    let global = unsafe { SCDynamicStoreCopyValue(store.raw(), key.raw()) };
    let global = OwnedCf::new(global, "SCDynamicStoreCopyValue").ok()?;
    if unsafe { CFGetTypeID(global.raw()) } != unsafe { CFDictionaryGetTypeID() } {
        return None;
    }
    let primary_key = cf_string("PrimaryService").ok()?;
    dictionary_string(global.raw(), primary_key.raw())
}

pub(crate) fn read_primary_status() -> Result<SystemProxyStatus, String> {
    let statuses = read_statuses()?;
    if let Some(primary) = primary_service_id() {
        if let Some((_, status)) = statuses.iter().find(|(id, _)| *id == primary) {
            return Ok(status.clone());
        }
    }
    statuses
        .into_iter()
        .next()
        .map(|(_, status)| status)
        .ok_or_else(|| "没有可用的 macOS 网络服务，无法判定系统代理".into())
}

#[cfg(test)]
mod tests;
