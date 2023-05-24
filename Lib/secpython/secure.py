import ast
import operator as op
import sys

operators = {
    ast.Or: op.or_,
    ast.And: op.and_,
    ast.Not: op.not_,
}

def sec_eval(expr, dic = {}):
    try:
        return eval_(ast.parse(expr, mode="eval").body, dic)
    except (TypeError, SyntaxError, KeyError) as e:
        raise ValueError(
            f"{expr!r} is not a valid or supported logic expression"
        ) from e

def eval_(node, dic):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return dic[node.id]
    elif isinstance(node, ast.BoolOp):
        op = operators[ast.Or if (isinstance(node.op, ast.Or)) else ast.And]
        op(True, False)
        values = node.values
        result = eval_(values[0], dic)
        for i in range(1, len(values)):
            result = op(result, eval_(values[i], dic))
        return result
    elif isinstance(node, ast.UnaryOp):
        return operators[type(node.op)](eval_(node.operand, dic))
    else:
        raise TypeError(node)

def unsecure(make_dangerous_expr = None):
    """
        it's a wrapper that help us to propagate the unsecure data
    """
    def unsecure_outer(fn):
        def unsecure_inner(*args, **kwargs):
            response = fn(*args, **kwargs)
            if (response is not None):
                dangerous_dic = {}
                for key in kwargs.keys():
                    dangerous_dic[key] = is_dangerous(kwargs[key])
                for i in range(len(args)):
                    key = "x_%s"%(str(i))
                    if (key in kwargs):
                        raise SystemError("There two variables with the same name!")
                    dangerous_dic[key] = is_dangerous(args[i])
                do_dangerous = sec_eval(make_dangerous_expr, dangerous_dic) if make_dangerous_expr != None else True
                
                if do_dangerous:
                    make_dangerous(response)
                else:
                    make_secure(response)
            return response
        return unsecure_inner
    return unsecure_outer
    
def code_injection(code_injection_expr):
    """
        it's a wrapper that help us to add to Python Runtime Audit Hooks the code_injection event
    """
    def code_injection_outer(fn):
        def code_injection_inner(*args, **kwargs):
            code_injection_dic = {}
            for key in kwargs.keys():
                code_injection_dic[key] = is_dangerous(kwargs[key])
            for i in range(len(args)):
                key = "x_%s"%(str(i))
                if (key in kwargs):
                    raise SystemError("There two variables with the same name!")
                code_injection_dic[key] = is_dangerous(args[i])
        
            is_code_injection = sec_eval(code_injection_expr, code_injection_dic)
            
            sys.audit("code_injection", is_code_injection)
            response = fn(*args, **kwargs)
            return response
        return code_injection_inner
    return code_injection_outer

    
    
