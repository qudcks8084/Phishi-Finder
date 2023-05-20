from difflib import SequenceMatcher

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

url1 = "www.naver.com."
url2 = "www.nexon.com."
spurl1 = url1.split('.')
spurl2 = url2.split('.')
cnturl1 = url1.count('.')
cnturl2 = url2.count('.')

if (cnturl1 == cnturl2) :
    if (cnturl1 == 3):
        sum = 0
        for i in range(0,cnturl1):
            sum = sum + similar(spurl1[i],spurl2[i])
        similarity = sum / cnturl1
        print(url1," 과 ",url2 , "간의 유사도는 : ", round(similarity*100), "% 입니다.")
    
    a = similar(url1,url2)
    print(url1," 과 ",url2 , "간의 유사도는 : ", round(a*100), "% 입니다.")
else :
    print("올바르지 않은 비교대상입니다.")


