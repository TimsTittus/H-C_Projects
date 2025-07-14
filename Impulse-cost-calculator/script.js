function calculateCost() {
  const price = parseFloat(document.getElementById('price').value);
  const wage = parseFloat(document.getElementById('wage').value);
  const resultDiv = document.getElementById('result');

  if (price > 0 && wage > 0) {
    const hours = (price / wage).toFixed(2);
    resultDiv.textContent = `This will cost you ${hours} hours of work.`;
  } else {
    resultDiv.textContent = '';
  }
}