# importing the required modules
import argparse
from os import path
from getopt import getopt
import whois
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
import whois
import warnings



warnings.filterwarnings("ignore")

#dataset Cleaning:
def makeTokens(f):

  tkns_BySlash = str(f.encode('utf-8')).split('/') # make tokens after splitting by slash
  total_Tokens = []

  for i in tkns_BySlash:
    tokens = str(i).split('-') # make tokens after splitting by dash
    tkns_ByDot = []

  for j in range(0,len(tokens)):
    temp_Tokens = str(tokens[j]).split('.') # make tokens after splitting by dot
    tkns_ByDot = tkns_ByDot + temp_Tokens
    total_Tokens = total_Tokens + tokens + tkns_ByDot
    total_Tokens = list(set(total_Tokens))  #remove redundant tokens

  if 'com' in total_Tokens:
    total_Tokens.remove('com') # removing .com since it occurs a lot of times and it should not be included in our features
 
  return total_Tokens

def prediction(urls):
	urls_data = pd.read_csv("data/urldata.csv")
	print("===============Checking URLs===============")
	#add features and labels:
	url_list = urls_data["url"]
	y = urls_data["label"]

	#create tokens from the clean text and store into variable x
	vectorizer = TfidfVectorizer(tokenizer=makeTokens)
	X = vectorizer.fit_transform(url_list)

	#Data splitting: (80% for training and 20% for testing)
	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
	print("===============Testing Provided URLs===============")

	#model building using LogisticRegression, for classifying good and bad url
	logit = LogisticRegression() #create the model

	logit.fit(X_train, y_train) #fir the model on our training dataset
	
	print("=============================================")
	print("Prediction Accuracy of Model = ",logit.score(X_test, y_test))
	print("=============================================")

	#make predictions
	X_predict = urls
	X_predict = vectorizer.transform(X_predict)
	New_predict = logit.predict(X_predict)
	
	dictionary_pred = dict(zip(urls, New_predict))
	for website, prediction in dictionary_pred.items():
          print("Website = ", website, " ----->", prediction)

def check_reg(name):
    try:
        domain_info = whois.whois(name)
        return True
    except:
        return False

#takes in txt file and returns the list of lines without line breaks, clean text
def readtxtfile(txtfile):
	with open(txtfile) as file_in:
		lines = []
		for line in file_in:
			lines.append(line.rstrip('\n'))
		return lines

def password_check(passwd):
	
	SpecialSym =['$', '@', '#', '%']
	val = True
	
	if len(passwd) < 6:
		print('length should be at least 6')
		val = False
		
	if len(passwd) > 20:
		print('length should be not be greater than 8')
		val = False
		
	if not any(char.isdigit() for char in passwd):
		print(passwd,'Password should have at least one numeral')
		val = False
		
	if not any(char.isupper() for char in passwd):
		print(passwd,'Password should have at least one uppercase letter')
		val = False
		
	if not any(char.islower() for char in passwd):
		print(passwd,'Password should have at least one lowercase letter')
		val = False
		
	if not any(char in SpecialSym for char in passwd):
		print(passwd,'Password should have at least one of the symbols $@#')
		val = False
	if val:
		return val



def main():
	# create parser object
	parser = argparse.ArgumentParser(description = "A Program to analyse website of vulnerabilities")
	
	parser.add_argument("-f", "--url", type = str, nargs = 2,
						metavar=('path', 'function'), default = None,
						help = "Input the path for txt file and specify the function as second argument (MaliciousURL,Domain,SSL,Phishing). Checks the txt file of specified function")

	parser.add_argument("-u", "--website", type = str, nargs = 2,
						metavar=('path', 'function'), default = None,
						help = "Specify the single URL as 1st argument and function as 2nd argument (MaliciousURL,Domain,SSL,Phishing)")

	parser.add_argument("-p","--passwordchecker", type= str, nargs = 1,
						 default=None,
						help = "Specify the password for password check")

	# parse the arguments from standard input
	args = parser.parse_args()


	if args.url != None:
		file_path = args.url[0]
		if path.exists(file_path):
			lines = readtxtfile(file_path)
			if(args.url[1])  == "MaliciousURL":
					prediction(lines)

			elif(args.url[1])  == "Domain":
				for line in lines:
					if check_reg(line):

						print(line +" is registered!")
					else:
						print(line +" is not registered")

			elif (args.url[1]) == "SSL":
				print("call function for ssl")
				#call function here

			elif args.url[1] == "Phishing":
				print("call the phishing function here")

			else:
				print("Wrong arguments!")
		else:
			print("Specified txt file path does not exist!")

	elif args.website !=None:
		website_url = args.website[0]
		if(args.website[1]) == "MaliciousURL":
			#process one URL got error
			prediction(website_url)
		elif(args.website[1]) == "Domain":
			if check_reg(website_url):
				print(website_url + " is registered!")
			else:
				print(website_url + " is not registered!")
		elif(args.website[1]) == "SSL":
			print("SSL")
		elif(args.website[1]) == "Phishing":
			print("Phishing")

	elif args.passwordchecker !=None:
		passwd = args.passwordchecker[0]
		if path.exists(passwd):
			passw = readtxtfile(passwd)
			for p in passw:
				if (password_check(p)):
					print(p +" is a valid password!")


	

if __name__ == "__main__":
	# calling the main function
	main()
	

