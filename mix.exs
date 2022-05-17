defmodule Pcp.MixProject do
  use Mix.Project

  def project do
    [
      app: :pcp,
      version: "0.0.1",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: [:asn1] ++ Mix.compilers
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:asn1ex, "~> 0.0.1"}  # https://github.com/vicentfg/asn1ex
    ]
  end
end
