using System;
using System.Collections.Generic;
using System.Linq;

namespace HashLib4CSharp.PerformanceBenchmark
{
    internal static class Program
    {
        internal static void Main(string[] args)
        {
            var patterns = new List<string>();
            if (args?.Length > 0)
                patterns.AddRange(args);
            else
                patterns.Add(".*");

            Console.WriteLine("Benchmarking hashes whose names match: {0}",
                string.Join(", ", patterns.Select(s => $"'{s}'")));
            Console.WriteLine("Please be patient, this might take some time \n\r");

            try
            {
                foreach (var result in PerformanceBenchmark.DoBenchmark(patterns))
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