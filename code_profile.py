import enumNG
import cProfile


##################################################################
# Main function
##################################################################
def main():
    cProfile.run("enumNG.main()", sort ='tottime')


if __name__ == "__main__":
    main()