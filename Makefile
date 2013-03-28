CC = gcc

LIBS = 


PROG_NAMESEND = SendArp

PROG_NAMESNIFFER = SnifferArp

PROSE = SendArp.c 

PROSN = SnifferArp.c

SEND = ${PROSE:.c=.o}

SNIFFER = ${PROSN:.c=.o}


all: ${PROG_NAMESEND} ${PROG_NAMESNIFFER}

${PROG_NAMESEND} : ${SEND}
  ${CC} -o ${PROG_NAMESEND} ${SEND} 

${PROG_NAMESNIFFER} : ${SNIFFER}
	${CC} -o ${PROG_NAMESNIFFER} ${SNIFFER} 



clean:
	rm -f *.o  ${PROG_NAMESEND} ${PROG_NAMESNIFFER}

rebuild:
	clean all
