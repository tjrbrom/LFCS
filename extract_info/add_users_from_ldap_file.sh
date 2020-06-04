#!/bin/bash

# extract the user names
for i in $(cat ldapusers) # for every line in ldapusers
do
	USER=${i%%,*} # will remove everything behind comma
	USER=${USER#*=} # will remove everything in front of the equals sign
	echo $USER >> users
done

# shows that useradd is called for every user in users
for j in $(cat users)
do
	echo useradd $j
done

rm users

