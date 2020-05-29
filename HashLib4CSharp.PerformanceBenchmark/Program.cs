using System;
using System.Collections.Generic;

namespace HashLib4CSharp.PerformanceBenchmark
{
    internal static class Program
    {
        internal static void Main()
        {
            Console.WriteLine("Please be patient, this might take some time \n\r");

            try
            {
                foreach (var result in PerformanceBenchmark.DoBenchmark())
                    Console.WriteLine(result);

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