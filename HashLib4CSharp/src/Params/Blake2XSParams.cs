
namespace HashLib4CSharp.Params
{
    /// <summary>
    /// <b>Blake2XSConfig</b> is used to configure hash function parameters and
    /// keying.
    /// </summary>
    public sealed class Blake2XSConfig
    {
        public Blake2SConfig Config { get; set; }
        public Blake2STreeConfig TreeConfig { get; set; }

        private Blake2XSConfig(Blake2SConfig config, Blake2STreeConfig treeConfig)
        {
            Config = config;
            TreeConfig = treeConfig;
        }

        public Blake2XSConfig Clone() => new Blake2XSConfig(Config?.Clone(), TreeConfig?.Clone());

        public static Blake2XSConfig CreateBlake2XSConfig(Blake2SConfig config, Blake2STreeConfig treeConfig) =>
            new Blake2XSConfig(config, treeConfig);
    }
}