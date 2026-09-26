import { parse } from '@babel/parser';

const PARSER_OPTIONS = Object.freeze({
  sourceType: 'unambiguous',
  errorRecovery: true,
  allowReturnOutsideFunction: true,
  allowAwaitOutsideFunction: true,
  allowImportExportEverywhere: true,
  attachComment: false,
  ranges: false,
  tokens: false,
});

/**
 * Parses JavaScript into a Babel AST. Returns null when the file cannot be parsed even with
 * error recovery; the caller records that as a low-weight finding because heavily broken or
 * non-JavaScript content is itself worth a look.
 */
export function parseSource(sourceText) {
  try {
    return parse(sourceText, PARSER_OPTIONS);
  } catch {
    return null;
  }
}
