package common

import (
	"time"
)

type cache interface {
	SetCacheTime(int64) //if arg < 0, just update alive time
	IsAlive() bool
	DeInit()
}

type cacheContainer struct {
	c map[string]cache
}

func (container *cacheContainer) UpdateCache(key string, c cache) {
	container.c[key] = c
}

func (container *cacheContainer) AddCache(key string, c cache, cacheTime int64) {
	container.DelCache(key)
	container.c[key] = c
	c.SetCacheTime(cacheTime)
}

func (container *cacheContainer) GetCache(key string) cache {
	v, bHave := container.c[key]
	if bHave {
		if v.IsAlive() {
			return v
		} else {
			container.DelCache(key)
		}
	}
	return nil
}

func (container *cacheContainer) DelCache(key string) bool {
	v, bHave := container.c[key]
	if bHave {
		v.DeInit()
		delete(container.c, key)
		return true
	}
	return false
}

func (container *cacheContainer) DelAllCache() {
	for key, _ := range container.c {
		container.DelCache(key)
	}
}

var g_CacheMgr map[string]*cacheContainer

func init() {
	g_CacheMgr = make(map[string]*cacheContainer)
	go func() {
		c := time.Tick(time.Second * 30)
		for _ = range c {
			for k, cache := range g_CacheMgr {
				for key, info := range cache.c {
					if !info.IsAlive() {
						info.DeInit()
						delete(cache.c, key)
					}
				}
				if len(cache.c) == 0 {
					delete(g_CacheMgr, k)
				}
			}
		}
	}()
}

func GetCacheContainer(key string) *cacheContainer {
	c, bHave := g_CacheMgr[key]
	if bHave {
		return c
	}
	c = &cacheContainer{c: make(map[string]cache)}
	g_CacheMgr[key] = c
	return c
}

func DelCacheContainer(key string) {
	c, bHave := g_CacheMgr[key]
	if bHave {
		c.DelAllCache()
	}
	delete(g_CacheMgr, key)
}

func DelAllCacheContainer() {
	for key, c := range g_CacheMgr {
		c.DelAllCache()
		delete(g_CacheMgr, key)
	}
}
