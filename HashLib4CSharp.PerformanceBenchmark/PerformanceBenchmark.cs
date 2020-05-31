using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;

namespace HashLib4CSharp.PerformanceBenchmark
{
    internal static class PerformanceBenchmark
    {
        private static Random Random { get; }

        static PerformanceBenchmark() => Random = new Random();

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

        private static IEnumerable<IHash> InstantiateHashes(IReflect type)
        {
            var methodInfos = type.GetMethods(BindingFlags.Public |
                                              BindingFlags.Static);

            var infos = methodInfos.Where(methodInfo =>
                methodInfo.GetParameters().Length == 0 ||
                methodInfo.GetParameters().All(parameterInfo => parameterInfo.IsOptional));

            return infos.Select(info => new {info, parameterInfos = info.GetParameters()})
                .Select(t => ((IHash) t.info.Invoke(null,
                    t.parameterInfos.Length == 0
                        ? null
                        : Enumerable.Repeat(Type.Missing, t.parameterInfos.Length).ToArray()))?.Clone());
        }

        private static IEnumerable<IHash> GetAllHashInstances()
        {
            return GetNestedTypesRecursively(typeof(HashFactory))
                .Where(t => t.IsClass && t.IsAbstract && t.IsSealed)
                .SelectMany(InstantiateHashes)
                .Concat(GetBlakeHashes());

            IEnumerable<Type> GetNestedTypesRecursively(Type root)
            {
                foreach (var type in root.GetNestedTypes(BindingFlags.Public))
                {
                    yield return type;
                    foreach (var child in GetNestedTypesRecursively(type))
                        yield return child;
                }
            }

            IEnumerable<IHash> GetBlakeHashes()
            {
                yield return HashFactory.Crypto.CreateBlake2BP(64, new byte[0]);
                yield return HashFactory.Crypto.CreateBlake2SP(32, new byte[0]);
            }
        }

        public static IEnumerable<string> DoBenchmark(IEnumerable<string> patterns)
        {
            var tasks = GetAllHashInstances().Where(h => patterns.Any(p => Regex.IsMatch(h.Name, p)))
                .Select(hash => Task.Run(() => Calculate(hash))).ToList();

            while (tasks.Count > 0)
            {
                var taskArray = tasks.ToArray();
                _ = Task.WaitAny(taskArray);

                tasks.Clear();
                foreach (var task in taskArray)
                {
                    if (task.IsCompleted)
                        yield return task.Result;
                    else
                        tasks.Add(task);
                }
            }
        }
    }
}