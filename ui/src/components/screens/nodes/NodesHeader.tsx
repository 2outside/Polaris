import type { TFunction } from 'i18next';
import type { DialogDesc } from '@/components/dialogs/dialog-store';
import type { AnchoredMenu } from '@/lib/use-anchored-menu';

interface Props {
  t: TFunction;
  statsText: string;
  testAll: () => void;
  testing: boolean;
  addMenu: boolean;
  setAddMenu: React.Dispatch<React.SetStateAction<boolean>>;
  addWrapRef: React.RefObject<HTMLDivElement | null>;
  addAnchored: AnchoredMenu<HTMLButtonElement, HTMLDivElement>;
  openDialog: (dialog: DialogDesc) => void;
  setActiveTab: (id: string) => void;
  openMeshJoin: () => void;
}

/** 页头（`.phead`）：全部测速 + 「添加」下拉（手动添加 / 组网接入 / 手动导入 / 添加订阅）。 */
export function NodesHeader({
  t,
  statsText,
  testAll,
  testing,
  addMenu,
  setAddMenu,
  addWrapRef,
  addAnchored,
  openDialog,
  setActiveTab,
  openMeshJoin,
}: Props) {
  return (
    <div className="phead">
      <div className="ph-title">
        <h1>{t('sidebar.server')}</h1>
        <span className="nd-count">{statsText}</span>
      </div>
      <div className="acts">
        <button
          type="button"
          className="btn ghost"
          onClick={testAll}
          disabled={testing}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
            <path d="M13 2L4 14h6l-1 8 9-12h-6z" />
          </svg>
          <span>{t('nodes.testAll')}</span>
        </button>
        <div ref={addWrapRef} style={{ position: 'relative' }}>
          <button
            ref={addAnchored.anchorRef}
            type="button"
            className="btn flow"
            aria-haspopup="menu"
            aria-expanded={addMenu}
            onClick={() => setAddMenu((v) => !v)}
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
              <path d="M12 5v14M5 12h14" />
            </svg>
            <span>{t('nodes.add')}</span>
            <svg viewBox="0 0 24 24" className="nd-chev" fill="none" stroke="currentColor" strokeWidth={1.9}>
              <path d="M6 9l6 6 6-6" />
            </svg>
          </button>
          {addMenu && (
            <div
              ref={addAnchored.menuRef}
              className="mini-menu"
              role="menu"
              style={addAnchored.style}
            >
              <button
                type="button"
                className="mi"
                role="menuitem"
                onClick={() => {
                  setAddMenu(false);
                  setActiveTab('manual');
                  openDialog({ kind: 'node' });
                }}
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
                  <path d="M12 20h9M16.5 3.5a2.1 2.1 0 013 3L7 19l-4 1 1-4z" />
                </svg>
                <span>{t('nodes.manualAdd')}</span>
              </button>
              <button
                type="button"
                className="mi"
                role="menuitem"
                onClick={() => {
                  setAddMenu(false);
                  openMeshJoin();
                }}
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
                  <path d="M9 15l6-6M8 8a3 3 0 10-3 3M16 16a3 3 0 103 3" />
                </svg>
                <span>{t('nodes.meshAddAccess')}</span>
              </button>
              <div className="mm-sep" role="separator" />
              <button
                type="button"
                className="mi"
                role="menuitem"
                onClick={() => {
                  setAddMenu(false);
                  openDialog({ kind: 'import', onAdded: () => setActiveTab('manual') });
                }}
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
                  <path d="M12 15V4M8 8l4-4 4 4M4 15v3a2 2 0 002 2h12a2 2 0 002-2v-3" />
                </svg>
                <span>{t('nodes.manualImport')}</span>
              </button>
              <button
                type="button"
                className="mi"
                role="menuitem"
                onClick={() => {
                  setAddMenu(false);
                  openDialog({ kind: 'sub', onAdded: setActiveTab });
                }}
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
                  <path d="M4 11a9 9 0 019 9M4 4a16 16 0 0116 16" />
                </svg>
                <span>{t('nodes.addSubscription')}</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
