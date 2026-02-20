// A safe PicoClaw calculator skill

function calculate(expression) {
  const sanitized = expression.replace(/[^0-9+\-*/.() ]/g, '');
  return Function(`"use strict"; return (${sanitized})`)();
}

module.exports = { calculate };
