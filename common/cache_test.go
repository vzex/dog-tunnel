package common

import "testing"

type m struct {
	T int
	w int
}

func (*m) IsAlive() bool        { return true }
func (*m) SetCacheTime(t int64) {}
func (*m) DeInit()              { println("deinit") }

func TestCache(t *testing.T) {
	cache := GetCacheContainer("test")
	cache2 := GetCacheContainer("test2")
	println("addcache", "mmnn", "aabb")
	cache.AddCache("mm", &m{1, 2}, 0)
	cache.AddCache("nn", &m{3, 4}, 0)
	cache2.AddCache("aa", &m{1, 2}, 0)
	cache2.AddCache("bb", &m{3, 4}, 0)
	a := cache.GetCache("mm")
	b := cache.GetCache("mm")
	b.(*m).T = 12
	if (a.(*m)).T != 12 {
		t.Error("cache value copied!!")
	}
	if cache2.GetCache("novalue") != nil {
		t.Error("cache should be nil!!")
	}
	println("delcache", "mmnn", "aabb")
	DelAllCacheContainer()
}
