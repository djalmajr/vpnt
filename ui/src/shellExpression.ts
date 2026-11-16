/** Detect copied shell syntax without evaluating or changing the value. */
export function hasShellExpression(value: string): boolean {
  return /\$[({]|`/.test(value);
}
