# Password Dictionary Generator

## Options
| Argument             | Description                                                         |
| -------------------- | ------------------------------------------------------------------- |
| -l\<min length\>     | Minimum length of the generated passwords                           |
| -m\<max length\>     | Maximum length of the generated passwords                           |
| -r\<max occurences\> | Maximum number of repeated occurrences for each charater            |
| -p \<base string\>   | Base string to derive passwords ("use this way for blanks")         |
| -d                   | Add to the base string only symbols and numbers                     |
| -L                   | Leet variations for letters, numbers and symbols (eqivalent to -ANS)|
| -A                   | Leet variations for letters                                         |
| -N                   | Leet variations for numbers                                         |
| -S                   | Leet variations for symbols                                         |


## Compile
```
$ gcc -o passwdgen passwdgen.c
```


## Usage

```
$ passwdgen -l5 -m9 -A -p "passwd" > passwd_dictionary.txt
```


