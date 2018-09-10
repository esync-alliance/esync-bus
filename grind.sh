#valgrind --tool=memcheck --leak-check=full --track-origins=yes $@  # track-origins fails after introducing mmap files
valgrind --tool=memcheck --leak-check=full $@
