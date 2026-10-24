# HOMEii 8 — גרסת ניסיון

גרסת בטא נפרדת: **HOMEii Network Monitor Beta**. הגרסה הקיימת והנתונים שלה נשארים במקומם. לבטא מסד נתונים נפרד וכתובת בפורט **8384**.

## התקנה

1. ב־Home Assistant פתח הגדרות ← תוספים ← חנות התוספים ← מאגרים.
2. הוסף את הכתובת הבאה במלואה:

   `https://github.com/r11a/homeii-network-monitor#feature/zabbix-local-8`

3. התקן **HOMEii Network Monitor Beta**, הפעל ולחץ **פתח ממשק**. ההתקנה הראשונה בונה את חבילת התוסף ועשויה להימשך מספר דקות. אין צורך בשרת Zabbix נפרד.
4. בכניסה ישירה: `http://כתובת-השרת:8384`. צור משתמש מנהל בכניסה הראשונה. בכניסה דרך Home Assistant מזוהה משתמש ה־Ingress.

## בדיקה ראשונה

- לחץ **הוסף התקן**, הזן כתובת IP ושם ושמור. אפשר להוסיף גם התקן מנותק.
- המתן למדידה הראשונה — בדרך כלל עד שתי דקות. עד שיש מדידה מוצג מצב לא ידוע, ולא מצב תקין משוער.
- לחץ על ההתקן כדי לראות מדידות ב־24 השעות האחרונות. אפור מציין זמן ללא מדידות; התקנה חדשה אינה מכילה היסטוריה קודמת.
- בהגדרות הזן טווח רשת, לדוגמה `192.168.1.0/24`, והפעל גילוי. הגילוי עשוי להימשך עד עשר דקות. לחץ **הצג תוצאות גילוי** ואשר רק התקנים שברצונך לנטר.
- נתק התקן ניסוי ובדוק שהמצב מתעדכן. מצב הזמינות מתעדכן לפי מדידות; פתיחת התראה עשויה להמתין למספר כשלונות בהתאם לכלל Zabbix.
- הפעל מחדש את התוסף ובדוק שההתקנים וההיסטוריה נשמרו.

## מה כלול ומה עדיין מוגבל

כלולים מנוע Zabbix ו־PostgreSQL מקומיים, ניטור ICMP, הוספה ידנית, גילוי לאישור, חיפוש, עדיפות, אירועים ואישור טיפול, היסטוריית זמינות וממשק עברית/אנגלית. התקנים שאינם עונים ל־ICMP עלולים להופיע כמנותקים גם כשהם פועלים.

זו גרסת בדיקה: אין עדיין אשף SNMP, מחיקת התקנים בממשק החדש, זיהוי פיזי ודאי של התקן לאחר שינוי IP, או הוכחת קיבולת של אלפי התקנים. אין העברה אוטומטית של מלאי הגרסה הקודמת. ההתקנים וההיסטוריה של הגרסה הקודמת נשארים בתוסף הקודם.

החיבור ל־Home Assistant דורש את גרסת האינטגרציה מתוך ענף הבטא: בהגדרות HOMEii צור מפתח חיבור, ובמסך החיבור של האינטגרציה הזן את כתובת הבטא ואת המפתח. המפתח מיועד לקריאת נתונים בלבד. התקנת האינטגרציה והכרטיסים אינה אוטומטית בבטא זו. פעולות הניהול נעשות דרך ממשק התוסף. שילוב מלא נבדק בנפרד מהפעלת מנוע הניטור.

## עבודה בלי אינטרנט ושחזור

לאחר התקנה, המדידות, מסד הנתונים והממשק פועלים ללא אינטרנט. התקנה ועדכונים עדיין דורשים גישה להורדות או הכנת image מראש באתר מחובר; אין בבטא מתקין גרפי לאתר מנותק.

גיבוי התוסף ב־Home Assistant מוגדר כגיבוי קר: התוסף נעצר בזמן הגיבוי כדי לשמור מסד נתונים עקבי. הפסקת בדיקת הבטא פשוטה: עצור את תוסף הבטא וחזור לתוסף הקודם. אין צורך לשחזר או להמיר את נתוני הגרסה הקודמת.

לרישוי וקוד מקור ראה [THIRD_PARTY.md](THIRD_PARTY.md).

## Beta 3 — Operations

The Zabbix workspace now includes device metadata editing, pause/resume, 24-hour availability/latency/loss charts, 1/7/30-day per-device reports with explicit sample coverage and truncation, inventory CSV export, existing diagnostic tools, user administration, audit history, browser incident notifications and wall display. Discovery and report lists are paginated. Adapter identity is based on locally observed ARP and inferred names; it is not guaranteed physical identity.

Browser notifications require browser permission and the interface to remain open. For background notifications use Home Assistant automations. The legacy alert-rule editor is not connected to Zabbix events. Full backups use Home Assistant add-on backups, including PostgreSQL; legacy SQLite export is not a Zabbix backup.

The beta still does not provide an SNMP/agent setup wizard, server power/service commands, automatic migration or proven thousand-device capacity. Period reports have a 20,000-sample cap per metric; partial reports explicitly show this limit. No synthetic history is generated.
