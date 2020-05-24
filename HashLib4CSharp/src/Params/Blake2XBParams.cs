
namespace HashLib4CSharp.Params
{
    /// <summary>
    /// <b>Blake2XSConfig</b> is used to configure hash function parameters and
    /// keying.
    /// </summary>
    public sealed class Blake2XBConfig
    {
        public Blake2BConfig Config { get; set; }
        public Blake2BTreeConfig TreeConfig { get; set; }

        private Blake2XBConfig(Blake2BConfig config, Blake2BTreeConfig treeConfig)
        {
            Config = config;
            TreeConfig = treeConfig;
        }

        public Blake2XBConfig Clone() => new Blake2XBConfig(Config?.Clone(), TreeConfig?.Clone());

        public static Blake2XBConfig CreateBlake2XBConfig(Blake2BConfig config, Blake2BTreeConfig treeConfig) =>
            new Blake2XBConfig(config, treeConfig);
    }
}