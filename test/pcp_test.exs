defmodule PcpTest do
  use ExUnit.Case
  doctest Pcp

  test "greets the world" do
    assert Pcp.hello() == :world
  end
end
