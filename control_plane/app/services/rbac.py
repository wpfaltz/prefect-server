ROLE_RANK = {
    "reader": 1,
    "writer": 2,
    "admin": 3,
    "service": 3,
}


def can_set_mapping(actor_role: str) -> bool:
    """
    Pode alterar mappings?
    """
    return actor_role in ("admin", "writer", "service")


def can_assign_secret(actor_role: str, secret_assign_level: str) -> bool:
    """
    Pode atribuir um secret com determinado nível?
    """
    return ROLE_RANK.get(actor_role, 0) >= ROLE_RANK.get(secret_assign_level, 999)


def can_modify_principal(actor_role: str, target_role: str) -> bool:
    """
    Impede que alguém modifique usuário de mesmo nível ou superior.
    """
    return ROLE_RANK.get(actor_role, 0) > ROLE_RANK.get(target_role, 0)
