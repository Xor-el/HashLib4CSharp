using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;

namespace HashLib4CSharp.PerformanceBenchmark
{
    internal static class PerformanceBenchmark
    {
        private static Random Random { get; }

        static PerformanceBenchmark()
        {
            Random = new Random();
        }

        private static string Calculate(IHash hashInstance, string namePrefix = "", int size = 64 * 1024)
        {
            const uint threeSecondsInMilliseconds = 3000;
            var data = new byte[size];

            for (var i = 0; i < size; i++)
                data[i] = (byte) Random.Next(size);

            var maxRate = 0.0;
            var totalMilliSeconds = 0.0;

            for (var i = 0; i < 3; i++)
            {
                long total = 0;
                while (totalMilliSeconds <= threeSecondsInMilliseconds)
                {
                    var stopWatch = Stopwatch.StartNew();

                    hashInstance.ComputeBytes(data);
                    total += data.Length;

                    stopWatch.Stop();

                    // Get the elapsed time as a TimeSpan value.
                    var timeSpan = stopWatch.Elapsed;

                    totalMilliSeconds += timeSpan.TotalMilliseconds;
                }

                maxRate = Math.Max(total / (totalMilliSeconds / 1000) / 1024 / 1024, maxRate);
            }

            var newName = !string.IsNullOrWhiteSpace(namePrefix)
                ? string.Format($"{hashInstance.Name} {namePrefix}")
                : hashInstance.Name;

            return $"{newName} Throughput: {maxRate:0.00} MB/s with Blocks of {size / 1024} KB";
        }

        private static void GetAllHashInstance(IReflect type, ref List<IHash> hashInstances)
        {
            var methodInfos = type.GetMethods(BindingFlags.Public |
                                              BindingFlags.Static);

            var infos = methodInfos.Where(methodInfo =>
                methodInfo.GetParameters().Length == 0 || methodInfo.GetParameters().All(parameterInfo =>
                    parameterInfo.IsOptional));


            hashInstances.AddRange(infos.Select(info => new {info, parameterInfos = info.GetParameters()})
                .Select(t => ((IHash) t.info.Invoke(null,
                    t.parameterInfos.Length == 0
                        ? null
                        : Enumerable.Repeat(Type.Missing, t.parameterInfos.Length).ToArray()))?.Clone()));
        }


        public static void DoBenchmark(ref List<string> logger)
        {
            if (logger == null)
                throw new ArgumentNullException(nameof(logger));

            var hashInstances = new List<IHash>();

            foreach (var type in typeof(HashFactory).GetNestedTypes(BindingFlags.Public))
            {
                if (!type.IsClass || !type.IsAbstract || !type.IsSealed) continue;

                GetAllHashInstance(type, ref hashInstances);

                foreach (var innerType in type.GetNestedTypes(BindingFlags.Public))
                {
                    if (!innerType.IsClass || !innerType.IsAbstract || !innerType.IsSealed) continue;

                    GetAllHashInstance(innerType, ref hashInstances);
                }
            }

            hashInstances.Add(HashFactory.Crypto.CreateBlake2BP(64, new byte[0]));
            hashInstances.Add(HashFactory.Crypto.CreateBlake2SP(32, new byte[0]));
            logger.AddRange(hashInstances.Select(hash => Calculate(hash)));
        }
    }
}