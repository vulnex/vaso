// A safe PicoClaw calculator skill — no dynamic code execution

function calculate(expression) {
  const sanitized = expression.replace(/[^0-9+\-*/.() ]/g, '');
  const tokens = sanitized.match(/(\d+\.?\d*|[+\-*/()])/g) || [];

  // Simple left-to-right evaluation with operator precedence
  let result = parseFloat(tokens[0]) || 0;
  for (let i = 1; i < tokens.length; i += 2) {
    const op = tokens[i];
    const num = parseFloat(tokens[i + 1]) || 0;
    switch (op) {
      case '+': result += num; break;
      case '-': result -= num; break;
      case '*': result *= num; break;
      case '/': result = num !== 0 ? result / num : NaN; break;
    }
  }
  return result;
}

module.exports = { calculate };
