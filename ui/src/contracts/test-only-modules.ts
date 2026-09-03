/**
 * "test-only module" naming convention, in one place.
 *
 * Three gates need the same notion and must not each keep their own copy:
 * - `i18n/i18n-coverage.test.ts` (G1) exempts these files from the bare-CJK rule, because their
 *   Chinese is developer-facing assertion text that never reaches a user;
 * - `i18n/i18n-coverage.test.ts` (G0-b) locks that exemption: product code must not import them;
 * - `contracts/file-naming.test.ts` accepts the `.test-support.` infix as a legal file name.
 *
 * Kept ASCII-only on purpose: this module is itself scanned by G1.
 */

/** `foo.test.ts` / `foo.spec.tsx` / `foo.test-support.ts` — never shipped in the app bundle. */
export const IS_TEST_ONLY_MODULE = /\.(test|spec|test-support)\.tsx?$/;

/** Only the fixture/helper half: imported by tests, never by product code. */
export const IS_TEST_SUPPORT_MODULE = /\.test-support\.tsx?$/;
