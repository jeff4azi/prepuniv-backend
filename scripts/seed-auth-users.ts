/**
 * seed-auth-users.ts
 *
 * Creates REAL, loggable-into Supabase Auth accounts matching the
 * seeded public.profiles rows in 20260810000006_seed_data.sql.
 *
 * Uses the service-role key + supabase.auth.admin.createUser so we can
 * force the exact UUIDs that the seeded profiles expect (otherwise the
 * FK from profiles.id → auth.users.id would be orphaned).
 *
 * Password for every account: PrepUniv123!
 *
 * Usage:
 *   cd prepuniv-backend
 *   npx tsx scripts/seed-auth-users.ts
 */

import "dotenv/config";
import { createClient } from "@supabase/supabase-js";

const required = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
for (const env of required) {
  if (!process.env[env]) {
    console.error(`❌ Missing env var ${env} — check prepuniv-backend/.env`);
    process.exit(1);
  }
}

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  },
);

const PASSWORD = "PrepUniv123!";

/**
 * MUST match the UUIDs seeded in 006_seed_data.sql profiles table exactly.
 * id === auth.users.id === profiles.id
 */
const SEED_USERS = [
  // --- Admins ---
  {
    id: "dddddddd-0001-4000-8000-000000000001",
    email: "admin@prepuniv.com",
    full_name: "Super Admin",
  },
  {
    id: "dddddddd-0002-4000-8000-000000000002",
    email: "jeffrey@prepuniv.com",
    full_name: "Jeffrey Austin",
  },
  // --- Approved creators ---
  {
    id: "cccccccc-0001-4000-8000-000000000001",
    email: "amaka.okafor@unilag.edu.ng",
    full_name: "Dr. Amaka Okafor",
  },
  {
    id: "cccccccc-0002-4000-8000-000000000002",
    email: "ibrahim.musa@abu.edu.ng",
    full_name: "Prof. Ibrahim Musa",
  },
  {
    id: "cccccccc-0003-4000-8000-000000000003",
    email: "chidi.eze@unilag.edu.ng",
    full_name: "Chidi Eze",
  },
  // --- Regular users ---
  {
    id: "aaaaaaaa-0001-4000-8000-000000000001",
    email: "adebayo.j@example.com",
    full_name: "Adebayo Johnson",
  },
  {
    id: "aaaaaaaa-0002-4000-8000-000000000002",
    email: "ifeoma.nwosu@abu.edu.ng",
    full_name: "Ifeoma Nwosu",
  },
  {
    id: "aaaaaaaa-0003-4000-8000-000000000003",
    email: "suleiman.garba@abu.edu.ng",
    full_name: "Suleiman Garba",
  },
  {
    id: "aaaaaaaa-0004-4000-8000-000000000004",
    email: "chisom.eze@unn.edu.ng",
    full_name: "Chisom Eze",
  },
  {
    id: "aaaaaaaa-0005-4000-8000-000000000005",
    email: "aisha.yusuf@unn.edu.ng",
    full_name: "Aisha Yusuf",
  },
  {
    id: "aaaaaaaa-0006-4000-8000-000000000006",
    email: "oluwatobi.a@unilag.edu.ng",
    full_name: "Oluwatobi Adewale",
  },
  {
    id: "aaaaaaaa-0007-4000-8000-000000000007",
    email: "miriam.okonkwo@unilag.edu.ng",
    full_name: "Miriam Okonkwo",
  },
  {
    id: "aaaaaaaa-0008-4000-8000-000000000008",
    email: "babatunde.alabi@abu.edu.ng",
    full_name: "Babatunde Alabi",
  },
  {
    id: "aaaaaaaa-0009-4000-8000-000000000009",
    email: "zainab.mohammed@abu.edu.ng",
    full_name: "Zainab Mohammed",
  },
  // --- Creator applicants ---
  {
    id: "eeeeeeee-0001-4000-8000-000000000001",
    email: "ngozi.adeyemi@unilag.edu.ng",
    full_name: "Ngozi Adeyemi",
  },
  {
    id: "eeeeeeee-0002-4000-8000-000000000002",
    email: "emeka.obi@abu.edu.ng",
    full_name: "Emeka Obi",
  },
  {
    id: "eeeeeeee-0003-4000-8000-000000000003",
    email: "fatima.bello@unn.edu.ng",
    full_name: "Fatima Bello",
  },
  {
    id: "eeeeeeee-0004-4000-8000-000000000004",
    email: "tunde.fasanya@unilag.edu.ng",
    full_name: "Tunde Fasanya",
  },
  {
    id: "eeeeeeee-0005-4000-8000-000000000005",
    email: "blessing.nwosu@unn.edu.ng",
    full_name: "Blessing Nwosu",
  },
];

async function main() {
  console.log(`🌱 Seeding ${SEED_USERS.length} auth users → ${process.env.SUPABASE_URL}`);
  console.log(`🔑 All accounts get password: ${PASSWORD}\n`);

  let created = 0;
  let skipped = 0;
  const errors: Array<{ email: string; error: string }> = [];

  for (const u of SEED_USERS) {
    const { data, error } = await supabase.auth.admin.createUser({
      id: u.id,
      email: u.email,
      password: PASSWORD,
      email_confirm: true,
      user_metadata: { full_name: u.full_name },
    });

    if (error) {
      // Supabase returns a specific error when the id already exists —
      // treat that as a skip, not a failure (idempotent re-runs).
      if (error.message?.includes("already") || error.code === "23505") {
        console.log(`⏭️  skip (exists): ${u.email}`);
        skipped++;
      } else {
        console.error(`❌ FAIL ${u.email}: ${error.message}`);
        errors.push({ email: u.email, error: error.message });
      }
      continue;
    }

    console.log(`✅ created: ${u.email}  (${data.user.role})`);
    created++;
  }

  console.log("\n─── Summary ───");
  console.log(`Created: ${created}`);
  console.log(`Skipped (already exist): ${skipped}`);
  console.log(`Errors: ${errors.length}`);
  if (errors.length) {
    console.error("\n─── Errors ───");
    errors.forEach((e) => console.error(`  ${e.email}: ${e.error}`));
    process.exit(1);
  }
  console.log("\n🎉 Done — you can now log in with any of the accounts above using password: " + PASSWORD);
}

main().catch((e) => {
  console.error("💥 Fatal:", e);
  process.exit(1);
});
