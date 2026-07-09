/*
 * Tiny self-authored fixture for idamesh end-to-end verification.
 *
 * A handful of small, distinctly named functions so that a decompiler produces
 * recognizable pseudocode and the function enumerator returns a non-empty page.
 * This source is ours; the compiled artifact is committed under tests/fixtures/.
 */
#include <stdio.h>

/*
 * Exported so the PE export directory carries the name verbatim; this makes at
 * least one user function deterministically resolvable by name in the database,
 * independent of library-signature recognition.
 */
__declspec(dllexport) int add_numbers(int a, int b)
{
    return a + b;
}

int multiply_numbers(int a, int b)
{
    int total = 0;
    int i;
    for (i = 0; i < b; i++)
    {
        total += a;
    }
    return total;
}

int accumulate(const int *values, int n)
{
    int sum = 0;
    int i;
    for (i = 0; i < n; i++)
    {
        sum += values[i];
    }
    return sum;
}

int main(void)
{
    int data[4] = {2, 4, 6, 8};
    int s = add_numbers(3, 4);
    int m = multiply_numbers(5, 6);
    int a = accumulate(data, 4);
    printf("%d %d %d\n", s, m, a);
    return 0;
}
