//! 托盘浮层几何：物理矩形 / 屏幕工作区 / 系统栏边缘推断 / 定位与尺寸落位（纯几何计算 + 少量
//! `tauri::WebviewWindow` 落位副作用）。从 `tray.rs` 整段搬出（Phase 4A 批 B6）。
//! `use super::window::{anchor, TRAY_EDGE_GAP_LOGICAL}` 回指兄弟模块 `window.rs`（批 B7 落地后
//! 两项已随浮层窗域迁走，此处不再经 façade 中转）。

use tauri::{AppHandle, LogicalSize, Manager, PhysicalPosition, PhysicalSize, Position, Size};

use super::window::{anchor, TRAY_EDGE_GAP_LOGICAL};

/// 托盘图标的屏幕物理矩形（左上角 + 尺寸）。`TrayIconEvent::Click` 的 `rect` 原样存这里。
/// `tray-icon` 的三平台事件契约均为物理坐标；尤其 Windows 源自 `Shell_NotifyIconGetRect`，不能再拿
/// 浮层窗当前屏的 DPI 猜一次转换比例。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PhysicalRect {
    pub(super) x: f64,
    pub(super) y: f64,
    pub(super) w: f64,
    pub(super) h: f64,
}

/// 一块显示器上的物理像素区域，边界采用左闭右开/上闭下开。窗口定位只认它，不把「整屏」与
/// 「扣掉任务栏/Dock/菜单栏后的工作区」混在同一组 `(position, size)` 参数里。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ScreenArea {
    pub(super) left: i32,
    pub(super) top: i32,
    pub(super) right: i32,
    pub(super) bottom: i32,
}

impl ScreenArea {
    fn new(position: &PhysicalPosition<i32>, size: &PhysicalSize<u32>) -> Self {
        Self {
            left: position.x,
            top: position.y,
            right: position.x.saturating_add(size.width as i32),
            bottom: position.y.saturating_add(size.height as i32),
        }
    }

    fn is_usable(self) -> bool {
        self.right > self.left && self.bottom > self.top
    }
}

/// 托盘所在的系统边缘；浮层朝相反方向（工作区内部）展开。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TrayEdge {
    Top,
    Bottom,
    Left,
    Right,
}

impl TrayEdge {
    fn attr(self) -> &'static str {
        match self {
            Self::Top => "top",
            Self::Bottom => "bottom",
            Self::Left => "left",
            Self::Right => "right",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct OverlayPlacement {
    work_area: ScreenArea,
    pub(super) edge: TrayEdge,
    pub(super) scale_factor: f64,
}

pub(super) fn physical_tray_rect(rect: tauri::Rect) -> Option<PhysicalRect> {
    let (Position::Physical(p), Size::Physical(s)) = (rect.position, rect.size) else {
        return None;
    };
    Some(PhysicalRect {
        x: f64::from(p.x),
        y: f64::from(p.y),
        w: f64::from(s.width),
        h: f64::from(s.height),
    })
}

fn valid_anchor(anchor: PhysicalRect) -> bool {
    anchor.x.is_finite()
        && anchor.y.is_finite()
        && anchor.w.is_finite()
        && anchor.h.is_finite()
        && anchor.w > 0.0
        && anchor.h > 0.0
}

pub(super) fn default_tray_edge() -> TrayEdge {
    if cfg!(target_os = "macos") {
        TrayEdge::Top
    } else {
        TrayEdge::Bottom
    }
}

fn edge_distance(anchor: PhysicalRect, screen: ScreenArea, edge: TrayEdge) -> f64 {
    match edge {
        TrayEdge::Top => (anchor.y - f64::from(screen.top)).abs(),
        TrayEdge::Bottom => (f64::from(screen.bottom) - (anchor.y + anchor.h)).abs(),
        TrayEdge::Left => (anchor.x - f64::from(screen.left)).abs(),
        TrayEdge::Right => (f64::from(screen.right) - (anchor.x + anchor.w)).abs(),
    }
}

fn work_inset(screen: ScreenArea, work: ScreenArea, edge: TrayEdge) -> i32 {
    match edge {
        TrayEdge::Top => work.top.saturating_sub(screen.top),
        TrayEdge::Bottom => screen.bottom.saturating_sub(work.bottom),
        TrayEdge::Left => work.left.saturating_sub(screen.left),
        TrayEdge::Right => screen.right.saturating_sub(work.right),
    }
    .max(0)
}

/// 从托盘锚点与同屏工作区推断系统栏所在边。工作区有保留边时只在这些边中选离锚点最近者：这能在
/// Windows 竖向任务栏的底角处打破“左/右与底边同距”的歧义，也能在 mac 同时存在顶部菜单栏与
/// 底部/侧边 Dock 时仍选中图标实际所在的顶部。自动隐藏使工作区等于整屏时，再退回四边最近距离；
/// 距离完全相同时保持平台默认（mac 顶、其余底）。
pub(super) fn resolve_tray_edge(
    anchor: Option<PhysicalRect>,
    screen: ScreenArea,
    work: ScreenArea,
    preferred: TrayEdge,
) -> TrayEdge {
    let Some(anchor) = anchor.filter(|anchor| valid_anchor(*anchor)) else {
        return preferred;
    };
    let edges = [
        preferred,
        TrayEdge::Top,
        TrayEdge::Bottom,
        TrayEdge::Left,
        TrayEdge::Right,
    ];
    let has_reserved_edge = edges
        .iter()
        .copied()
        .any(|edge| work_inset(screen, work, edge) > 0);
    let mut best: Option<(TrayEdge, f64)> = None;
    for edge in edges {
        if has_reserved_edge && work_inset(screen, work, edge) == 0 {
            continue;
        }
        let distance = edge_distance(anchor, screen, edge);
        if best.is_none_or(|(_, best_distance)| distance < best_distance) {
            best = Some((edge, distance));
        }
    }
    best.map(|(edge, _)| edge).unwrap_or(preferred)
}

/// 托盘锚点中心点是选屏的唯一权威：不再看浮层窗上一次停留的 `current_monitor()`。Tauri 的
/// `monitor_from_point` 在 Windows 直达 `MonitorFromPoint`，`work_area()` 直达 `GetMonitorInfoW.rcWork`；
/// 因而多屏负坐标、异 DPI 与任务栏保留区都来自同一个 monitor 事实源。无有效锚点才回退主屏。
pub(super) fn overlay_placement(
    app: &AppHandle,
    anchor: Option<PhysicalRect>,
) -> Option<OverlayPlacement> {
    let anchor = anchor.filter(|anchor| valid_anchor(*anchor));
    let monitor = anchor
        .and_then(|anchor| {
            app.monitor_from_point(anchor.x + anchor.w / 2.0, anchor.y + anchor.h / 2.0)
                .ok()
                .flatten()
        })
        .or_else(|| app.primary_monitor().ok().flatten())?;
    let screen = ScreenArea::new(monitor.position(), monitor.size());
    let monitor_work = monitor.work_area();
    let work = ScreenArea::new(&monitor_work.position, &monitor_work.size);
    let work = if work.is_usable() { work } else { screen };
    Some(OverlayPlacement {
        work_area: work,
        edge: resolve_tray_edge(anchor, screen, work, default_tray_edge()),
        scale_factor: monitor.scale_factor(),
    })
}

/// 首帧前播种托盘边缘，供 CSS 把卡片的透明留白移到**远离**系统栏的一侧；四个方向的外边距总量不变，
/// 所以不会让 `tray_resize` 高度或固定窗宽发生二次抖动。运行期热开到另一块屏时由同一个 setter 更新。
pub(super) fn tray_edge_boot_script(edge: TrayEdge) -> String {
    format!(
        r#"(function () {{
  window.__POLARIS_TRAY_EDGE__ = '{edge}';
  function apply() {{
    var el = document.documentElement;
    if (el) el.setAttribute('data-tray-edge', window.__POLARIS_TRAY_EDGE__);
  }}
  window.__POLARIS_SET_TRAY_EDGE__ = function (next) {{
    if (window.__POLARIS_TRAY_EDGE__ === next) return;
    window.__POLARIS_TRAY_EDGE__ = next;
    apply();
  }};
  apply();
  document.addEventListener('readystatechange', apply);
  document.addEventListener('DOMContentLoaded', apply);
}})();"#,
        edge = edge.attr()
    )
}

fn apply_tray_edge(win: &tauri::WebviewWindow, edge: TrayEdge) {
    let _ = win.eval(format!(
        "window.__POLARIS_SET_TRAY_EDGE__ && window.__POLARIS_SET_TRAY_EDGE__('{}');",
        edge.attr()
    ));
}

/// 纯几何：由锚点（图标屏幕物理矩形）+ **同屏工作区** + 窗口尺寸 + 系统栏边缘算浮层左上角。
/// 有锚点时只沿系统栏方向按图标中心对齐；垂直于系统栏的坐标始终以工作区边界为准。后者不能取锚点
/// 边缘：Windows 隐藏图标面板里的图标位于工作区内部，拿它定位会把菜单额外抬高一整行。无/退化锚点
/// 时贴该边的右下惯用角。最终只在同一工作区内 clamp，绝不跨回浮层旧屏或主屏。
pub(super) fn overlay_xy(
    anchor: Option<PhysicalRect>,
    work: ScreenArea,
    win_size: (u32, u32),
    gap: i32,
    edge: TrayEdge,
) -> (i32, i32) {
    let wsw = i32::try_from(win_size.0).unwrap_or(i32::MAX);
    let wsh = i32::try_from(win_size.1).unwrap_or(i32::MAX);

    let (x, y) = match anchor.filter(|anchor| valid_anchor(*anchor)) {
        Some(a) => {
            let cx = (a.x + a.w / 2.0).round() as i32 - wsw / 2;
            let cy = (a.y + a.h / 2.0).round() as i32 - wsh / 2;
            match edge {
                TrayEdge::Top => (cx, work.top + gap),
                TrayEdge::Bottom => (cx, work.bottom - wsh - gap),
                TrayEdge::Left => (work.left + gap, cy),
                TrayEdge::Right => (work.right - wsw - gap, cy),
            }
        }
        None => match edge {
            TrayEdge::Top => (work.right - wsw - gap, work.top + gap),
            TrayEdge::Bottom => (work.right - wsw - gap, work.bottom - wsh - gap),
            TrayEdge::Left => (work.left + gap, work.bottom - wsh - gap),
            TrayEdge::Right => (work.right - wsw - gap, work.bottom - wsh - gap),
        },
    };
    let x = x.clamp(work.left, work.right.saturating_sub(wsw).max(work.left));
    let y = y.clamp(work.top, work.bottom.saturating_sub(wsh).max(work.top));
    (x, y)
}

/// 把浮层对齐到**托盘图标**并夹回屏内。锚点来自 `TrayIconEvent::Click` 的 `rect`（OS 给的图标屏幕矩形，
/// 本来就是物理像素）。真正的几何在 [`overlay_xy`]（纯函数、可单测）；本函数只负责按锚点中心找
/// monitor/work area、同步 CSS 边缘并下发 `set_position`。取不到显示器信息 → 保持当前位置（不猜坐标）。
pub(super) fn reposition(win: &tauri::WebviewWindow) {
    let app = win.app_handle();
    let anchor = anchor(app);
    let Some(placement) = overlay_placement(app, anchor) else {
        return;
    };
    let ws = win.outer_size().unwrap_or(PhysicalSize::new(280, 420));
    // gap 按**锚点所在屏**的缩放折成物理像素。Windows 对齐普通托盘弹窗的 12px；macOS 维持
    // 菜单栏面板的 1px。卡片近系统栏侧的 CSS margin 为 0，不再二次叠加透明高度。
    let gap = (TRAY_EDGE_GAP_LOGICAL * placement.scale_factor)
        .round()
        .max(1.0) as i32;
    apply_tray_edge(win, placement.edge);
    let (x, y) = overlay_xy(
        anchor,
        placement.work_area,
        (ws.width, ws.height),
        gap,
        placement.edge,
    );
    let _ = win.set_position(PhysicalPosition::new(x, y));
}

// ── 浮层 React 端 → 主进程的专用薄 command ─────────────────────────────────────

/// 逻辑尺寸按托盘锚点所在屏的缩放折成物理像素。纯函数单测钉住：这里不掺任何装饰边框补偿；
/// Windows 的浮层已经是无装饰窗，目标值就是最终 HWND/viewport 的尺寸。
#[cfg(any(target_os = "windows", test))]
pub(super) fn overlay_physical_size(
    width: f64,
    height: f64,
    scale_factor: f64,
) -> PhysicalSize<u32> {
    LogicalSize::new(width, height).to_physical(scale_factor)
}

/// Windows 的 TAO 0.35 `set_inner_size` 在这类 transparent + undecorated HWND 上会把请求高度扩大
/// 20px；renderer 的 ResizeObserver 随即把扩大后的 viewport 再上报，形成 420→440→…→720 的正反馈。
/// Win32 `SetWindowPos` 直接设置已无非客户区的 HWND 外框，真机验证其 Window/Client/DWM 三个矩形相等，
/// 因而这里按目标物理尺寸一次落位；不写“减 20”这种只对当前系统样式成立的补丁常量。
#[cfg(target_os = "windows")]
pub(super) fn set_overlay_size(
    win: &tauri::WebviewWindow,
    width: f64,
    height: f64,
    scale_factor: f64,
) -> Result<(), String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SetWindowPos, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER,
    };

    let size = overlay_physical_size(width, height, scale_factor);
    let width = i32::try_from(size.width).map_err(|_| "托盘浮层宽度超出 Win32 范围".to_string())?;
    let height =
        i32::try_from(size.height).map_err(|_| "托盘浮层高度超出 Win32 范围".to_string())?;
    let hwnd = win.hwnd().map_err(|e| e.to_string())?;
    // SAFETY: hwnd 由仍存活的 `WebviewWindow` 持有；调用不保存句柄，只同步改当前无装饰窗的尺寸，
    // 且 SWP_NOMOVE/NOZORDER/NOACTIVATE 保持位置、层级与焦点不变。
    let ok = unsafe {
        SetWindowPos(
            hwnd.0,
            std::ptr::null_mut(),
            0,
            0,
            width,
            height,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
pub(super) fn set_overlay_size(
    win: &tauri::WebviewWindow,
    width: f64,
    height: f64,
    _scale_factor: f64,
) -> Result<(), String> {
    win.set_size(LogicalSize::new(width, height))
        .map_err(|e| e.to_string())
}
