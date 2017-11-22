# py_omen
Python implimentation of the OMEN password cracker originally developed by RUB-SysSec. The original RUB-SysSec github repo is:

https://github.com/RUB-SysSec/OMEN

OMEN: Ordered Markov ENumerator*
-----------
*The following is taken from the original OMEN Github page at https://github.com/RUB-SysSec/OMEN/blob/master/README.md

OMEN is a Markov model-based password guesser written in C. It generates password candidates according to their occurrence probabilities, i.e., it outputs most likely passwords first. OMEN significantly improves guessing speed over existing proposals.
If you are interested in the details on how OMEN improves on existing Markov model-based password guessing approaches, please refer to [OMEN: Faster Password Guessing Using an Ordered Markov Enumerator](https://hal.archives-ouvertes.fr/hal-01112124/file/omen.pdf).

User Guide
-----------
Like the original OMEN program, this distro consisits of two seperate python scripts, `createNG` and `enumNG`. `createNG`
calculates n-gram probabilities based on a given list of passwords and stores them
in a ruleset for later use. Based on these probabilities `enumNG` enumerates new
passwords in the decending probability order, with the most probable password guesses created first. Please note, some of the command line options for these programs
are slightly different from the original OMEN program


### Installation

These programs were written for Python3. They have been tested with Python3.5.1 but any version of Python3 should work.

It is *highly* recommended that you also install the `chardet` python package to autodect character encoding during the training phase.
While not required, if you do not use it you will have to manually specify the character encoding of the training password set on the
command line. You can get `chardet` from:

https://github.com/chardet/chardet

or simply use the command:

`pip3 install chardet`

### Basic Usage

There is a default ruleset included with this git repo called 'Default'. If you do not specify a ruleset on the command line, the default
one will be used.

To create your own ruleset, use `createNG`. To calculate the probabilities, `createNG` must be
called giving a path to a password list that should be trained:

`$ python3 ./createNG  -t password-training-list.txt -r RULENAME` 

Each password of the given list must be in a new line. The module then
reads and evaluates the list generating a couple of files. All the associated probabilities and config files are saved in the
`Rules\<RULENAME>\` directory.

A useful and recommended command line flag is the `-a SIZE_OF_ALPHABET` option. It will cause the OMEN trainer to learn an alphabet
of characters from the training set vs using the built-in default one. The `SIZE_OF_ALPHABET` option says how many of the most probable
characters found in the training set should be used. Chances are you'll want to set it to something like 90 to 100. For example, on the
RockYou training set if you set it to 20, the following characters will be part of the alphabet `ae1ionrls20tm3c98dy5`

`$ python3 ./createNG  -t password-training-list.txt -r RULENAME -a 100` 

If you do not have chardet installed or want to override the results of it you can use the `-e ENCODING` option

`$ python3 ./createNG  -t password-training-list.txt -r RULENAME -a ASCII`

You can also specify the length of the ngrams to use in OMEN using the `-n NGRAM_SIZE` option. By default this is set to `4`. A ngram
is how many characters are used in the conditional probability runs. For example with a settiong of 4 it will look at the string 'abc'
then calculate the next letter, which in this case will likely be 'd'. The longer you set it, the more disk-space the ruleset will take up
and it will also start to have a performance impact. On the plus side, it may also make your ruleset more precise which is the whole
reason you are probably using OMEN vs pure bruteforce!

`$ python3 ./createNG  -t password-training-list.txt -r RULENAME -n 4`

To generate password guesses to stdout for use in other password cracking programs, `enumNG` can be used to generate a list of passwords ordered by probabilities. 

`$ python3 ./enumNG -r RULENAME`

`enumNG` also supports saving and restaring sessions. To give a cracking session a name use the `-s SESSION_NAME` option. By default it
saves all sesions as `default`. Sessions will be periodically saved and will also save before shutting down if a `CNTRL-C` is detected.

`$ python3 ./enumNG -r RULENAME -s SESSION_NAME`

To restore a session, use the `--restore SESSION_NAME` option. Note, if you change the version of enumNG or retrain the Ruleset between session
the session will no longer be able to successfully restore, (since it is not saving the full ruleset, just indexes for it). If this is an issue for you please open a bug report on this git repo and
I'll see what I can do.

`$ python3 ./enumNG -r RULENAME --restore SESSION_NAME`

For research purposes, you can also limit the number of guesses that are generated using the `-m NUMBER_OF_GUESSES` command line flag

`$ python3 ./enumNG -r RULENAME -m 100000000`

Both modules provide a help dialog which can be shown using the `-h` or `--help` argument.
