#include <stdio.h>

int add_numbers(int a, int b) { return a + b; }

int multiply(int x, int y) {
  int result = x * y;
  return result;
}

void print_hello() { printf("Hello, World!\n"); }

int main() {
  int a = 5, b = 10;
  int sum = add_numbers(a, b);
  int product = multiply(a, b);

  print_hello();
  printf("Sum: %d, Product: %d\n", sum, product);

  return 0;
}
