#include <ourcontract.h>
#include <string.h>

typedef struct {
    char name[50];
    char pubkey[50];
    int votes;          // number of votes this user gets
    int vote_for;       // index of the user this user votes for
} user;

static struct {
    int is_freezed;     // true if the vote already ended
    int user_count;
    user users[100];
} state;

static int find_user(const char *name)
{
    int i;
    for (i = 0; i < state.user_count; i++) {
        if (str_cmp(name, state.users[i].name, 50) == 0) {
            return i;
        }
    }

    return -1;
}

static int sign_up(const char *name, const char *pubkey)
{
    if (state.is_freezed == 1) return -1;

    /* already signed up */
    if (find_user(name) != -1) return -1;

    /* number of users reaches upper bound */
    if (state.user_count == 100) return -1;

    str_printf(state.users[state.user_count].name, 50, "%s", name);
    str_printf(state.users[state.user_count].pubkey, 50, "%s", pubkey);
    state.users[state.user_count].votes = 0;
    state.users[state.user_count].vote_for = -1;
    out_printf("%s\n", state.users[state.user_count].name);

    state.user_count++;

    return 0;
}

static void state_init()
{
    state.is_freezed = 0;
    state.user_count = 0;
    out_clear();
}

/*
 * argv[0]: contract id
 * argv[1]: subcommand
 * argv[2...]: args
 */
int contract_main(int argc, char **argv)
{
    if (state_read(&state, sizeof(state)) == -1) {
        err_printf("state_init()\n");
        /* first time call */
        state_init();
        state_write(&state, sizeof(state));
        state_read(&state, sizeof(state));
    }

    if (argc < 2) {
        err_printf("%s: no subcommand\n", argv[0]);
        return 0;
    }

    /* subcommand "sign_up" */
    if (str_cmp(argv[1], "sign_up", 7) == 0) {
        if (argc != 4) {
            err_printf("%s: usage: sign_up user_name user_pubkey\n", argv[0]);
            return 0;
        }

        int ret = sign_up(argv[2], argv[3]);
        if (ret != 0) {
            err_printf("%s: sign_up failed\n", argv[0]);
            return 0;
        }

        state_write(&state, sizeof(state));
        return 0;
    } else if (strcmp(argv[1], "print") == 0) {
        err_printf("%d\n", state.user_count);
    }

    return 0;
}
