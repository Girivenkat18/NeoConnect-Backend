export function addWorkingDays(start: Date, days: number) {
  const cursor = new Date(start);
  let added = 0;

  while (added < days) {
    cursor.setDate(cursor.getDate() + 1);
    const day = cursor.getDay();
    if (day !== 0 && day !== 6) {
      added += 1;
    }
  }

  return cursor;
}

export function hasExceededWorkingDays(start: string, days: number, now = new Date()) {
  return addWorkingDays(new Date(start), days).getTime() <= now.getTime();
}
