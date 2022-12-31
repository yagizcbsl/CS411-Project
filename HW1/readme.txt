Mehmet Yağız Çebişli - 28229

# Question 1

# If we use the implemented Affine_Dec function and make 
# the key.gamma = 1 and key.theta to shift amount it will be shift cipher

I tried all possible keys since the key space is not large (26)

# When the possible_words printed it can be seen that there are 2 meaningful words,
# which are 'SLEEP' and 'BUNNY'


# Question 2
# I used the countLetters function and observed that
# two most frequent letters are 'S':18 and 'Z':25

# One of the most frequent letters is 'T' and there is a high probability that other one is 'E'

# Possible scenario - 1 --- 'S' and 'T', 'Z' and 'E' matched 
# key.gamma* 18 + key.theta = 19 % 26 and key.gamma*25 + key.theta = 4 % 26
key.gamma = 9
key.theta = 13
# This one does not produce a meaningful sentence so I went for the other possible scenario

# Possible scenario - 2 --- 'S' and 'E', 'Z' and 'T' matched 
# key.gamma* 18 + key.theta = 4 % 26 and key.gamma*25 + key.theta = 19 % 26
key.gamma = 17
key.theta = 10
# Scenario 2 produced a meaningful word which is,
# "THOUGH THIS BE MADNESS, YET THERE IS METHOD IN IT."
# so the decryption key is -> gamma (inverse of alpha) is 17 and theta (inverse of beta) is 10

# Now encryption key needs to be found
# It is known that 19*key.alpha + key.beta = 25 % 26 and 4*key.alpha + key.beta = 18 % 26
key.alpha = 23
key.beta = 4
# I checked and the found encryption key is also working


# Question 3

# There are 28*28 possible (double space is counted as well) bigrams so the modulus is 28*28 = 784
# and key space is the count of the numbers that are relatively prime with 784 which is 336


# Question 4

# It is secure against the letter frequency analysis. Because there are no letter bigram that is
# relatively more frequent than the other ones. 


# Question 5

# the Last character is '.' and plen = 1 (mod 2) so the last bigram must be ".X"

# It was known that the last 2 characters encrypted to the "YT" FROM ".X". This is because it can be said that
# 691*key.gamma + key.theta = 751 % 784. So each possible key.gamma,key.theta pair have been tried (336 of them, gamma's are the ones that are relatively prime with 784)
# and it is observed that the only meaningful plain text is "I HAVE COME TO BELIEVE THAT THE WHOLE WORLD IS AN ENIGMA." and key.gamma,key.theta pair is 89,404

# Decryption key pair is known so encrpytion key can be found
key.alpha = modinv(key.gamma,784)
key.beta = (691 - 751 * key.alpha) % 784
# I checked and the found encryption key is also working

# Question 6

It is known that pa is 1/29 for all letters in Turkish Alphabet.
For pb lets investigate a case for a random letter. (Let's say T)

One possible scenerio is we select 'A' as letter and 23 as shift amount, probability of this scenerio is 1/29 * 1/29
There are 29 scenarios like that for the letter 'T' so pb = 29 * 1/29 * 1/29 = 1/29
Furthermore, we can tell the same for all letters.



# Question 7

# First I got rid of all the punctuation and spaces.
# Then to find the length of the key vector I shifted the ciphertext by 1 and count the coincidences
# Then I incremented the shift amount and do the same 100 times. With this information, it can be observed
# that key vector size is 6

# I divided the cipher text into 6 subtexts and made a frequency analysis on each of them
# Except for the 2nd subtext when I matched the most frequent character with 'E' all of them decrypted succesfully
# For the 2nd subtext I matched the second most frequent one with 'E'
# Then I merged all subtexts to obtain:

HEWALKEDATTHEOTHERSHEELSWITHASWINGTOHISSHOULDERSANDHISLEGSSPREADUNWITTINGLYASIFTHELEVELFLOORSWERETILTINGUPANDSINKINGDOWNTOTHEHEAVEANDLUNGEOFTHESEATHEWIDEROOMSSEEMEDTOONARROWFORHISROLLINGGAITANDTOHIMSELFHEWASINTERRORLESTHISBROADSHOULDERSSHOULDCOLLIDEWITHTHEDOORWAYSORSWEEPTHEBRICABRACFROMTHELOWMANTELHERECOILEDFROMSIDETOSIDEBETWEENTHEVARIOUSOBJECTSANDMULTIPLIEDTHEHAZARDSTHATINREALITYLODGEDONLYINHISMINDBETWEENAGRANDPIANOANDACENTRETABLEPILEDHIGHWITHBOOKSWASSPACEFORAHALFADOZENTOWALKABREASTYETHEESSAYEDITWITHTREPIDATIONHISHEAVYARMSHUNGLOOSELYATHISSIDESHEDIDNOTKNOWWHATTODOWITHTHOSEARMSANDHANDSANDWHENTOHISEXCITEDVISIONONEARMSEEMEDLIABLETOBRUSHAGAINSTTHEBOOKSONTHETABLEHELURCHEDAWAYLIKEAFRIGHTENEDHORSEBARELYMISSINGTHEPIANOSTOOLHEWATCHEDTHEEASYWALKOFTHEOTHERINFRONTOFHIMANDFORTHEFIRSTTIMEREALIZEDTHATHISWALKWASDIFFERENTFROMTHATOFOTHERMENHEEXPERIENCEDAMOMENTARYPANGOFSHAMETHATHESHOULDWALKSOUNCOUTHLYTHESWEATBURSTTHROUGHTHESKINOFHISFOREHEADINTINYBEADSANDHEPAUSEDANDMOPPEDHISBRONZEDFACEWITHHISHANDKERCHIEF


