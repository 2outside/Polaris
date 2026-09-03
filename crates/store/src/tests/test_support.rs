//! ════════════════════════════════════════════════════════════════════════════
//! 测试基础设施：内存 MockFs（实现 ConfigFs，不触碰宿主 FS）+ FsOp 记录。
//! ════════════════════════════════════════════════════════════════════════════

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::fs::ConfigFs;
use crate::StoreError;

/// 记录的 FS 操作（用于断言 atomic_write 的 tmp→rename 顺序）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsOp {
    Write(PathBuf, String),
    Rename(PathBuf, PathBuf),
    Mkdir(PathBuf),
    Copy(PathBuf, PathBuf),
    Remove(PathBuf),
}

#[derive(Debug, Default)]
struct MockFsInner {
    files: HashMap<PathBuf, String>,
    ops: Vec<FsOp>,
}

/// 内存文件系统 mock（实现 ConfigFs，不触碰宿主 FS）。
/// 内部用 RefCell 实现 &self 下的可变性（对齐 ConfigFs 的 &self 签名，运行时 std::fs 亦 &self）。
#[derive(Debug, Default)]
pub struct MockFs {
    inner: RefCell<MockFsInner>,
}

impl MockFs {
    /// 预置一个文件（用于测试 setup）。
    pub fn with(self, path: &Path, content: impl Into<String>) -> Self {
        self.inner
            .borrow_mut()
            .files
            .insert(path.to_path_buf(), content.into());
        self
    }

    /// 取所有记录的操作（断言用）。
    pub fn operations(&self) -> Vec<FsOp> {
        self.inner.borrow().ops.clone()
    }

    /// 取文件内容快照（断言用）。
    pub fn snapshot(&self, path: &Path) -> Option<String> {
        self.inner.borrow().files.get(path).cloned()
    }
}

impl ConfigFs for MockFs {
    fn read_to_string(&self, path: &Path) -> Result<String, StoreError> {
        self.inner
            .borrow()
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| StoreError::Io(format!("not found: {}", path.display())))
    }

    fn write(&self, path: &Path, content: &str) -> Result<(), StoreError> {
        let mut inner = self.inner.borrow_mut();
        inner
            .ops
            .push(FsOp::Write(path.to_path_buf(), content.to_string()));
        inner.files.insert(path.to_path_buf(), content.to_string());
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), StoreError> {
        let mut inner = self.inner.borrow_mut();
        inner
            .ops
            .push(FsOp::Rename(from.to_path_buf(), to.to_path_buf()));
        let content = inner.files.remove(from);
        if let Some(c) = content {
            inner.files.insert(to.to_path_buf(), c);
            Ok(())
        } else {
            Err(StoreError::Io(format!("not found: {}", from.display())))
        }
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), StoreError> {
        self.inner
            .borrow_mut()
            .ops
            .push(FsOp::Mkdir(path.to_path_buf()));
        Ok(())
    }

    fn copy(&self, from: &Path, to: &Path) -> Result<(), StoreError> {
        let mut inner = self.inner.borrow_mut();
        inner
            .ops
            .push(FsOp::Copy(from.to_path_buf(), to.to_path_buf()));
        let content = inner.files.get(from).cloned();
        if let Some(c) = content {
            inner.files.insert(to.to_path_buf(), c);
            Ok(())
        } else {
            Err(StoreError::Io(format!("not found: {}", from.display())))
        }
    }

    fn exists(&self, path: &Path) -> bool {
        self.inner.borrow().files.contains_key(path)
    }

    fn remove(&self, path: &Path) -> Result<(), StoreError> {
        let mut inner = self.inner.borrow_mut();
        inner.ops.push(FsOp::Remove(path.to_path_buf()));
        inner.files.remove(path);
        Ok(())
    }

    fn list_dir(&self, dir: &Path) -> Result<Vec<String>, StoreError> {
        // 返回 parent==dir 的文件 basename（对齐 std::fs::read_dir 的直接子项语义）。
        let inner = self.inner.borrow();
        let names: Vec<String> = inner
            .files
            .keys()
            .filter(|p| p.parent() == Some(dir))
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
            .collect();
        Ok(names)
    }
}
