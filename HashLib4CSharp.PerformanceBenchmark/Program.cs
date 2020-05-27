using System;
using System.Collections.Generic;

namespace HashLib4CSharp.PerformanceBenchmark
{
    internal static class Program
    {
        internal static void Main()
        {
            var logger = new List<string>();

            Console.WriteLine("Please be patient, this might take some time \n\r");

            try
            {
                PerformanceBenchmark.DoBenchmark(ref logger);

                Console.WriteLine(string.Join("\n\r", logger));

                Console.WriteLine("\n\rPerformance Benchmark Finished");

                Console.ReadLine();
            }
            catch (Exception e)
            {
                Console.WriteLine($"{e} : {e.Message}");
            }
        }
    }
}