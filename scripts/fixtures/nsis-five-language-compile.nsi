; 最小 NSIS 3.11 模板探针：复现 Tauri 的 hook → MUI languages → custom-language-file 顺序。
; 手动验证：<nsis-3.11>/Bin/makensis /DOUTFILE=<temp-output.exe> scripts/fixtures/nsis-five-language-compile.nsi
Unicode true
!include "MUI2.nsh"
!include "..\\..\\src-tauri\\nsis-hooks.nsh"

Name "Polaris NSIS language contract"
Var UpdateMode
!ifdef OUTFILE
  OutFile "${OUTFILE}"
!else
  OutFile "nsis-five-language-compile.exe"
!endif

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "TradChinese"
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "Farsi"
!include "..\\..\\src-tauri\\nsis-languages\\Farsi.nsh"

Function .onInit
  StrCpy $UpdateMode 0
FunctionEnd

Section
  !insertmacro PolarisSelectLang $R8 "English" "简体中文" "繁體中文" "Русский" "فارسی"
  DetailPrint "$R8"
  !insertmacro NSIS_HOOK_PREINSTALL
  !insertmacro NSIS_HOOK_POSTINSTALL
  WriteUninstaller "$INSTDIR\\uninstall.exe"
SectionEnd

Section "Uninstall"
  !insertmacro NSIS_HOOK_POSTUNINSTALL
SectionEnd
