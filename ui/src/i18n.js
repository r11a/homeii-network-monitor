export const dictionaries = {
  he: {
    dashboard: 'סקירה', viewer: 'מרכז בקרה', devices: 'מכשירים', alerts: 'התראות', history: 'היסטוריה',
    tools: 'כלי רשת', settings: 'הגדרות', online: 'מחוברים', offline: 'מנותקים', unstable: 'לא יציבים',
    new: 'חדשים', critical: 'קריטיים', pinned: 'נעוצים', total: 'סה״כ מכשירים', openAlerts: 'התראות פתוחות',
    recentEvents: 'אירועים אחרונים', attention: 'דורשים טיפול', availability: 'זמינות', lastSeen: 'נראה לאחרונה',
    network: 'רשת', vendor: 'יצרן', category: 'קטגוריה', status: 'מצב', search: 'חיפוש מכשיר, IP או יצרן',
    all: 'הכול', scanNow: 'סריקה עכשיו', scanning: 'סורק', refresh: 'רענון נתונים', save: 'שמירה', cancel: 'ביטול',
    noData: 'אין נתונים להצגה', systemHealthy: 'המערכת תקינה', monitorLive: 'ניטור חי', resolve: 'פתור',
    run: 'הרץ בדיקה', target: 'כתובת יעד', ping: 'פינג', trace: 'ניתוב', ports: 'פורט פתוח', dns: 'DNS',
    speed: 'מהירות אינטרנט', general: 'כללי', appearance: 'מראה', language: 'שפה', theme: 'ערכת נושא',
    dark: 'כהה', light: 'בהירה', autoRefresh: 'רענון אוטומטי', historyDays: 'ימי שמירת היסטוריה',
    name: 'שם', ip: 'כתובת IP', actions: 'פעולות', edit: 'עריכה', close: 'סגירה', quarantine: 'הסגר', restore: 'החזרה',
    uptimeTrend: 'מגמת זמינות', networkPulse: 'דופק הרשת', last24h: '24 שעות אחרונות', deviceHealth: 'בריאות התקנים',
    enableNotifications: 'הפעל התראות PWA', notificationsUnsupported: 'הדפדפן אינו תומך בהתראות', notificationsDenied: 'הרשאת ההתראות לא אושרה', ready: 'מוכן', unavailable: 'לא זמין',
  },
  en: {
    dashboard: 'Overview', viewer: 'Command Center', devices: 'Devices', alerts: 'Alerts', history: 'History',
    tools: 'Network Tools', settings: 'Settings', online: 'Online', offline: 'Offline', unstable: 'Unstable',
    new: 'New', critical: 'Critical', pinned: 'Pinned', total: 'Total devices', openAlerts: 'Open alerts',
    recentEvents: 'Recent events', attention: 'Needs attention', availability: 'Availability', lastSeen: 'Last seen',
    network: 'Network', vendor: 'Vendor', category: 'Category', status: 'Status', search: 'Search device, IP or vendor',
    all: 'All', scanNow: 'Scan now', scanning: 'Scanning', refresh: 'Refresh data', save: 'Save', cancel: 'Cancel',
    noData: 'No data to display', systemHealthy: 'System healthy', monitorLive: 'Live monitoring', resolve: 'Resolve',
    run: 'Run test', target: 'Target address', ping: 'Ping', trace: 'Traceroute', ports: 'Open ports', dns: 'DNS',
    speed: 'Internet speed', general: 'General', appearance: 'Appearance', language: 'Language', theme: 'Theme',
    dark: 'Dark', light: 'Light', autoRefresh: 'Auto refresh', historyDays: 'History retention days',
    name: 'Name', ip: 'IP address', actions: 'Actions', edit: 'Edit', close: 'Close', quarantine: 'Quarantine', restore: 'Restore',
    uptimeTrend: 'Availability trend', networkPulse: 'Network pulse', last24h: 'Last 24 hours', deviceHealth: 'Device health',
    enableNotifications: 'Enable PWA notifications', notificationsUnsupported: 'Notifications are not supported by this browser', notificationsDenied: 'Notification permission was not granted', ready: 'Ready', unavailable: 'Unavailable',
  },
}

export function translator(language) {
  const dictionary = dictionaries[language] || dictionaries.he
  return (key) => dictionary[key] || key
}
