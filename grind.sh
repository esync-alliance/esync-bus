#valgrind --tool=memcheck --leak-check=full --track-origins=yes $@  # track-origins fails after introducing mmap files
# valgrind --tool=memcheck --leak-check=full --track-origins=yes $@
valgrind --track-origins=yes --error-limit=no --merge-recursive-frames=1 --tool=memcheck --leak-check=full --child-silent-after-fork=yes --gen-suppressions=all --log-file=v.log $@
