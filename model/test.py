from os import walk


file_name = []
for (dirpath,dirname,filename) in walk("/home/h4r15h/dataset/sniffy/splitted"):
    filename.extend(file_name)

counter = 0
for i in filename:
    if i[-3:] == "csv":
        print(i)
        counter += 1
print(counter)
