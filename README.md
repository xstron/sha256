# SHA-256 in C

## Introduction

I wrote this small C/C++ library because I wanted to learn more about the SHA-256 algorithm and the topic of hashing in general. I chose to write it in C because I wanted to squeeze as much performance as possible out of it and figured I could use the exercise.
There is also a link to the official SHA-256 Specification inside the header file for those who are interested.

## How to Use

Copy the file __libsha256.h__ into your project and #include it in your source code.

```
#include "libsha256.h"
```

Now you can use the function sha256 defined in the library/header file.
```
void sha256(uint8_t *message, size_t length, void *buffer_out);
```
The message parameter is a pointer to memory where the message that you want to hash is stored, length determines how many bytes of the message will be read, and buffer_out is the 256 bit large buffer where the final hash will be stored. 

For more info and example usage see `example.c`