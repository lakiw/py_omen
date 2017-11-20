import enumNG
import cProfile


##################################################################
# Main function
##################################################################
def main():
    cProfile.runctx("enumNG.main()", globals(), locals(), sort ='tottime')


if __name__ == "__main__":
    main()