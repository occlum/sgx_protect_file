# sgx_cipher

## Introduction

This is a command-line utility that encrypts and decrypts a file using SGX Protected File System Library.

## How to Build

To build the project, run the following command

    make

## How to Use

To encrypt a file with SGX Protected File System Library, run a command in the following format:

    ./sgx_protect_file encrypt -i <input_file> -o <output_file> -k <key>

To decrypt a file that is already encrypted, run a command in the following format:

    ./sgx_protect_file decrypt-i <input_file> -o <output_file> -k <key>

## TODOs

 [ ] Accept key argument (now hardcoded in the code)
 [ ] Use base64 encoding for key argument. See https://github.com/littlstar/b64.c.
