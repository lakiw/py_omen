#!/usr/bin/env python3

"""
Contains ascii art for the py_omen toolset
"""

import sys


def print_error():
    """
    ASCII art for displaying an error state before quitting

    Inputs:
        None
    
    Returns:
        None
    """

    print('',file=sys.stderr)
    print('An error occured, shutting down',file=sys.stderr)
    print('',file=sys.stderr)
    print(r' \__/      \__/      \__/      \__/      \__/      \__/          \__/',file=sys.stderr)
    print(r' (oo)      (o-)      (@@)      (xx)      (--)      (  )          (OO)',file=sys.stderr)
    print(r'//||\\    //||\\    //||\\    //||\\    //||\\    //||\\        //||\\',file=sys.stderr)
    print(r'  bug      bug       bug/w     dead      bug       blind      bug after',file=sys.stderr)
    print(r'         winking   hangover    bug     sleeping    bug     whatever you did',file=sys.stderr)
    print('',file=sys.stderr)

    
###################################################################################
# ASCII art for more generic failure
###################################################################################
def ascii_fail():
    """
    ASCII art for displaying a more generic error

    Inputs:
        None
    
    Returns:
        None
    """

    print(r"                                          __ ",file=sys.stderr)
    print(r"                                      _  |  |",file=sys.stderr)
    print(r"                  Yye                |_| |--|",file=sys.stderr)
    print(r"               .---.  e           AA | | |  |",file=sys.stderr)
    print(r"              /.--./\  e        A",file=sys.stderr)
    print(r"             // || \/\  e      ",file=sys.stderr)
    print(r"            //|/|| |\/\   aa a    |\o/ o/--",file=sys.stderr)
    print(r"           ///|\|| | \/\ .       ~o \.'\.o'",file=sys.stderr)
    print(r"          //|\|/|| | |\/\ .      /.` \o'",file=sys.stderr)
    print(r"         //\|/|\|| | | \/\ ( (  . \o'",file=sys.stderr)
    print(r"___ __ _//|/|\|/|| | | |\/`--' '",file=sys.stderr)
    print(r"__/__/__//|\|/|\|| | | | `--'",file=sys.stderr)
    print(r"|\|/|\|/|\|/|\|/|| | | | |",file=sys.stderr)
    print(r"",file=sys.stderr)