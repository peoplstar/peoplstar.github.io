import fileinput
import os

path = "./"
file_list = os.listdir(path)

value = 'categories'

for i in range(len(file_list)):
    with fileinput.input(file_list[i], inplace = True, encoding = "UTF-8") as f: 
        for line in f:        
            if line.startswith(value):            
                print('categories: Environment', end='\n')       
            else:           
                print(line, end='')
