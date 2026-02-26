ROLE_RANK = {
    "user": 0,
    "reader": 1,
    "writer": 2,
    "admin": 3,
    "service": 3,
}
"""Hierarquia numérica dos papéis (roles) do sistema RBAC.

Quanto maior o valor, maior o nível de privilégio. ``admin`` e ``service``
têm o mesmo nível (3). Utilizado para comparar se um ator pode operar
sobre recursos ou usuários de determinado nível.
"""


def can_set_mapping(actor_role: str) -> bool:
    """Verifica se o ator pode alterar mapeamentos de segredos.

    Apenas usuários com papel ``admin``, ``writer`` ou ``service``
    possuem permissão para criar, atualizar ou remover mapeamentos
    entre nomes genéricos e segredos reais.

    Args:
        actor_role: Papel do ator que está tentando a operação.

    Returns:
        bool: ``True`` se o ator tem permissão, ``False`` caso contrário.
    """
    return actor_role in ("admin", "writer", "service")


def can_assign_secret(actor_role: str, secret_assign_level: str) -> bool:
    """Verifica se o ator pode atribuir um segredo com determinado nível.

    Compara o rank numérico do papel do ator com o nível de atribuição
    (``assign_level``) do segredo. O ator só pode atribuir segredos cujo
    nível seja menor ou igual ao seu próprio papel na hierarquia.

    Args:
        actor_role: Papel do ator que está tentando a atribuição.
        secret_assign_level: Nível de atribuição requerido pelo segredo
            (``reader``, ``writer`` ou ``admin``).

    Returns:
        bool: ``True`` se o rank do ator é >= o nível do segredo.
    """
    return ROLE_RANK.get(actor_role, 0) >= ROLE_RANK.get(secret_assign_level, 999)


def can_modify_principal(actor_role: str, target_role: str) -> bool:
    """Verifica se o ator pode modificar um principal com determinado papel.

    Impede que um usuário altere dados de outro usuário cujo papel
    seja superior ao seu na hierarquia RBAC. O ator só pode modificar
    principals com rank menor ou igual ao seu.

    Args:
        actor_role: Papel do ator que está tentando a modificação.
        target_role: Papel do principal-alvo.

    Returns:
        bool: ``True`` se o ator pode modificar o alvo, ``False`` caso contrário.
    """
    return ROLE_RANK.get(actor_role, 0) >= ROLE_RANK.get(target_role, 0)
