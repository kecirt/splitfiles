from datetime import date
import time


def get_user_date():
    custom_choice = input("Custom choice?(y/n)")
    if(custom_choice == 'Y' or custom_choice == 'y'):
        user_date = input('Please enter the date (YYYY-MM-DD): ')
        try:
            year, month, day = map(int, user_date.split(('-')))
        except ValueError:
            print('Warning: Invalid format!')
            get_user_date()
        except UnboundLocalError:
            print('Come on!! Let\'s be serious here!!!')
            get_user_date()
        # final_date = 0
        if(year < 2018 or year > 2019):
            print('Warning: You entered ' + str(year) + ' as the year!!')
            year_choice = input("Are you sure about the year?(Y/n) ")
            if(year_choice == 'n' or year_choice == 'N'):
                get_user_date()
            elif(year_choice == 'y' or year_choice == 'Y'):
                try:
                    final_date = date(year, month, day).isoformat()
                except ValueError:
                    print("Kindly months are from 1-12 and dates from 1-31")
                    print("Error: Your input is not of YYYY-MM-DD format")
                    exit("Exiting..")
        try:
            final_date = date(year, month, day).isoformat()
        except ValueError:
            print("Either you month or date is out of range. Try again.")
            exit("Exiting..")
    elif(custom_choice.lower() == 'n'):
        print('Warning: Using today\'s date!!')
        final_date = time.strftime('%Y-%m-%d')
    # appending to another string+
    # final_date = str(final_date) + '-of-importance'
    # final_date = datetime.strptime(final_date, '%Y-%m-%d')
    return final_date


user_date = get_user_date()
print(user_date)
