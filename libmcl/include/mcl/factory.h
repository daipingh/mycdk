
#ifndef MCL_FACTORY_H_
#define MCL_FACTORY_H_

#include "lang.h"


#ifdef __cplusplus
#include <map>
#include <string>
#include <memory>
MCL_BEGIN_NAMESPACE(mcl)


/** 工厂注册类. */
template<class FactoryClass>
class FactoryRegistry
{
	typedef FactoryClass FactoryType;
	typedef FactoryRegistry<FactoryClass> RegistryType;
	typedef std::shared_ptr<FactoryClass> FactoryPointer;
	typedef std::map<const std::string, FactoryPointer> ContainerType;

public:
	/** 登记指定类型的工厂. */
	void registerFactory(const std::string &name, const FactoryPointer &factory)
	{
		auto r = factories.insert(typename ContainerType::value_type(name, factory));
		if (!r.second)
			r.first->second = factory;
	}

	/** 获取指定名称的工厂. */
	FactoryPointer getFactory(const std::string &name) const
	{
		auto ite = factories.find(name);
		return ite != factories.end() ? ite->second : FactoryPointer();
	}

	/** 获取默认工厂登记表. */
	MCL_NOINLINE static FactoryRegistry<FactoryClass> *registry(MCL_NOINLINE_DOTDOTDOT);

private:
	ContainerType factories;
};

/** 获取默认工厂登记表. */
template<class FactoryClass>
FactoryRegistry<FactoryClass> *FactoryRegistry<FactoryClass>::registry(MCL_NOINLINE_DOTDOTDOT)
{
	static FactoryRegistry<FactoryClass> s_registry;
	return &s_registry;
}


/** 登记指定类型的工厂到默认登记表. */
template<class FactoryClass, class FactoryClassImpl = FactoryClass>
struct RegisterFactory
{
	RegisterFactory(const std::string &name) {
		static auto s_factory = std::make_shared<FactoryClassImpl>();
		FactoryRegistry<FactoryClass>::registry()->registerFactory(name, s_factory);
	}
};

MCL_END_NAMESPACE
#endif

#endif
