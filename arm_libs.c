/*
 * Work around some spurious dependencies in some versions of ARM libgcc.
 * These would only be invoked in case of division by 0.
 */

void raise(int sig)
{
    return;
}

void __aeabi_unwind_cpp_pr0()
{
    return;
}
