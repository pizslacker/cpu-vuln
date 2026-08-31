cpu-vuln: cpu-vuln.c
	gcc -O3 -o cpu-vuln cpu-vuln.c
	strip cpu-vuln

clean:
	rm -f cpu-vuln
