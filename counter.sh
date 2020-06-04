COUNTER=$1
COUNTER=$((COUNTER * 2))
echo $COUNTER

minusone() {
	COUNTER=$(( COUNTER - 1 ))
	sleep 1 #wait for 1 sec
}

while [ $COUNTER -gt 0 ]
do
	echo you still have $COUNTER secs left
	minusone
done

[ $COUNTER = 0 ] && echo time\'s up && minusone

[ $COUNTER = -1 ] && echo one sec late! && minusone

while true
do
	echo you are now ${COUNTER#-} seconds late #removing the minus sign
	minusone
done

