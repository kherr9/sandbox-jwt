using System;

namespace Tests
{
    public static class DateTimeExtensions
    {
        public static int Epoc(this DateTime value)
        {
            var t = value - new DateTime(1970, 1, 1);
            return (int)t.TotalSeconds;
        }
    }
}